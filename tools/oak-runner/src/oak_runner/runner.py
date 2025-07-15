# src/oak_runner/runner.py
"""
Arazzo Workflow and OpenAPI Operation Runner

This library executes Arazzo workflows step-by-step, following the paths defined in the
workflow specification. It builds an execution tree based on the possible paths and
executes OpenAPI operations sequentially, handling success/failure conditions and flow control.
"""

import asyncio
import json
import logging
from collections.abc import Callable
from typing import Any, Union

import httpx
import requests

from .auth.auth_processor import AuthProcessor
from .auth.credentials.provider import CredentialProvider, CredentialProviderFactory
from .evaluator import ExpressionEvaluator
from .executor import StepExecutor
from .executor.server_processor import ServerProcessor
from .http import HTTPExecutor
from .models import (
    ActionType,
    ArazzoDoc,
    ExecutionState,
    OpenAPIDoc,
    RuntimeParams,
    StepStatus,
    WorkflowExecutionResult,
    WorkflowExecutionStatus,
)
from .utils import (
    deprecated,
    dump_state,
    load_arazzo_doc,
    load_openapi_file,
    load_source_descriptions,
)

logger = logging.getLogger("arazzo-runner")


class OAKRunner:
    """
    Executes Arazzo workflows step-by-step, following the defined paths
    and handling success/failure conditions
    """

    def __init__(
        self,
        arazzo_doc: ArazzoDoc | None = None,
        source_descriptions: dict[str, OpenAPIDoc] = None,
        http_client: Union[httpx.AsyncClient, requests.Session, None] = None,
        auth_provider: CredentialProvider | None = None
    ):
        """
        Initialize the runner with Arazzo document and source descriptions

        Args:
            arazzo_doc: Parsed Arazzo document
            source_descriptions: Dictionary of Open API Specs where the key is the source description name as defined in the Arazzo document
            http_client: Optional HTTP client for direct API calls (defaults to httpx.AsyncClient)
            auth_provider: Optional authentication provider
        """
        if not arazzo_doc and not source_descriptions:
            raise ValueError("Either arazzo_doc or source_descriptions must be provided.")

        self.arazzo_doc = arazzo_doc
        self.source_descriptions = source_descriptions

        # Process API authentication
        auth_processor = AuthProcessor()
        auth_config = auth_processor.process_api_auth(
            openapi_specs=source_descriptions,
            arazzo_specs=[arazzo_doc] if arazzo_doc else [],
        )

        if http_client is None:
            http_client = httpx.AsyncClient()
        
        self.auth_provider = auth_provider or CredentialProviderFactory.create_default(
            env_mapping=auth_config.get("env_mappings", {}),
            http_client=http_client,
            auth_requirements=auth_config.get("auth_requirements", []),
        )

        # Initialize HTTP client
        http_executor = HTTPExecutor(http_client, self.auth_provider)

        # Initialize step executor
        self.step_executor = StepExecutor(http_executor, self.source_descriptions)

        # Execution state
        self.execution_states = {}

        # Event callbacks
        self.event_callbacks = {
            "step_start": [],
            "step_complete": [],
            "workflow_start": [],
            "workflow_complete": [],
        }

    @classmethod
    def from_arazzo_path(cls, arazzo_path: str, base_path: str = None, http_client: Union[httpx.AsyncClient, requests.Session, None] = None, auth_provider=None):
        """
        Initialize the runner with an Arazzo document path

        Args:
            arazzo_path: Path to the Arazzo document
            base_path: Optional base path for source descriptions
            http_client: Optional HTTP client for direct API calls (defaults to httpx.AsyncClient)
        """
        if not arazzo_path:
            raise ValueError("Arazzo document path is required to initialize the runner.")

        arazzo_doc = load_arazzo_doc(arazzo_path)
        # For loading source descriptions, we can use requests temporarily for file operations
        temp_client = requests.Session() if http_client is None else http_client
        source_descriptions = load_source_descriptions(arazzo_doc, arazzo_path, base_path, temp_client)
        return cls(arazzo_doc, source_descriptions, http_client, auth_provider)

    @classmethod
    def from_openapi_path(cls, openapi_path: str):
        """
        Initialize the runner with a single OpenAPI specification path.

        Args:
            openapi_path: Path to the local OpenAPI specification file.
        """
        if not openapi_path:
            raise ValueError("OpenAPI specification path is required.")

        try:
            # Use the simplified utility function (no http_client needed)
            openapi_doc = load_openapi_file(openapi_path)
            source_descriptions = {"default": openapi_doc}
        except Exception as e:
            logger.error(f"Failed to load OpenAPI spec from {openapi_path}: {e}")
            raise ValueError(f"Could not load OpenAPI spec from {openapi_path}") from e

        # Initialize the runner without an Arazzo document
        # __init__ will create default http_client and auth_provider if needed
        return cls(
            arazzo_doc=None,
            source_descriptions=source_descriptions,
            http_client=None,
            auth_provider=None
        )

    def register_callback(self, event_type: str, callback: Callable):
        """
        Register a callback for workflow execution events

        Args:
            event_type: Type of event ('step_start', 'step_complete', 'workflow_start', 'workflow_complete')
            callback: Function to call when the event occurs
        """
        if event_type in self.event_callbacks:
            self.event_callbacks[event_type].append(callback)
        else:
            logger.warning(f"Unknown event type: {event_type}")

    def _trigger_event(self, event_type: str, **kwargs):
        """Trigger registered callbacks for an event"""
        for callback in self.event_callbacks.get(event_type, []):
            try:
                callback(**kwargs)
            except Exception as e:
                logger.error(f"Error in {event_type} callback: {e}")

    async def start_workflow(self, workflow_id: str, inputs: dict[str, Any] | None = None, runtime_params: RuntimeParams | None = None) -> str:
        """
        Start a new workflow execution

        Args:
            workflow_id: ID of the workflow to execute
            inputs: Input parameters for the workflow
            runtime_params: Optional runtime parameters for execution (e.g., server variables).

        Returns:
            execution_id: Unique ID for this workflow execution
        """
        # Generate a unique execution ID
        execution_id = f"{workflow_id}_{len(self.execution_states) + 1}"

        # Find the workflow definition
        workflow = None
        for wf in self.arazzo_doc.get("workflows", []):
            if wf.get("workflowId") == workflow_id:
                workflow = wf
                break

        if not workflow:
            raise ValueError(f"Workflow {workflow_id} not found in Arazzo document")

        # Execute dependency workflows if they exist
        depends_on = workflow.get("dependsOn", [])
        dependency_outputs = {}
        if depends_on:
            logger.info(f"Workflow {workflow_id} depends on {depends_on}")
            for dep_workflow_id in depends_on:
                logger.info(f"Executing dependency workflow: {dep_workflow_id}")
                # Execute the dependency workflow and wait for completion
                # Pass runtime_params to the dependent workflow execution
                dep_execution_id = await self.start_workflow(dep_workflow_id, inputs, runtime_params)

                # Run the dependency workflow until completion
                while True:
                    # execute_next_step will now retrieve runtime_params from the state
                    result = await self.execute_next_step(dep_execution_id)
                    if result.get("status") in [WorkflowExecutionStatus.WORKFLOW_COMPLETE, WorkflowExecutionStatus.ERROR]:
                        break

                # Get the dependency workflow outputs
                dep_state = self.execution_states.get(dep_execution_id)
                if not dep_state:
                    raise ValueError(
                        f"Dependency workflow execution state not found: {dep_execution_id}"
                    )

                # Store the dependency outputs for later use
                logger.info(
                    f"Dependency workflow {dep_workflow_id} outputs: {dep_state.workflow_outputs}"
                )
                dependency_outputs[dep_workflow_id] = dep_state.workflow_outputs.copy()
                # Double check dependency outputs are stored properly
                logger.info(
                    f"After storing dependency {dep_workflow_id}, dependency_outputs: {dependency_outputs}"
                )

                # Check if dependency succeeded
                if result.get("status") == WorkflowExecutionStatus.ERROR:
                    logger.error(f"Dependency workflow {dep_workflow_id} failed")
                    raise ValueError(f"Dependency workflow {dep_workflow_id} failed")

        # Initialize execution state
        state = ExecutionState(
            workflow_id=workflow_id,
            inputs=inputs or {},
            dependency_outputs=dependency_outputs, # Store dependency outputs
            runtime_params=runtime_params # Store runtime parameters in ExecutionState
        )

        # Initialize step statuses
        if workflow and "steps" in workflow:
            for step in workflow.get("steps", []):
                step_id = step.get("stepId")
                if step_id:
                    state.status[step_id] = StepStatus.PENDING

        # Store the execution state
        self.execution_states[execution_id] = state

        # Trigger workflow_start event
        self._trigger_event(
            "workflow_start", execution_id=execution_id, workflow_id=workflow_id, inputs=inputs
        )

        return execution_id

    async def execute_workflow(
        self,
        workflow_id: str,
        inputs: dict[str, Any] = None,
        runtime_params: RuntimeParams | None = None
    ) -> WorkflowExecutionResult:
        """
        Start and execute a workflow until completion, returning the outputs.

        Args:
            workflow_id: ID of the workflow to execute
            inputs: Input parameters for the workflow
            runtime_params: Runtime parameters for execution (e.g., server variables)

        Returns:
            A WorkflowExecutionResult object containing the status, workflow_id, outputs, and any error
        """
        def on_workflow_start(execution_id, workflow_id, inputs):
            logger.debug(f"\n=== Starting workflow: {workflow_id} ===")
            logger.debug(f"Inputs: {json.dumps(inputs, indent=2)}")

        def on_step_start(execution_id, workflow_id, step_id):
            logger.debug(f"\n--- Starting step: {step_id} ---")

        def on_step_complete(execution_id, workflow_id, step_id, success, outputs=None, error=None):
            logger.debug(f"--- Completed step: {step_id} (Success: {success}) ---")
            if outputs:
                logger.debug(f"Outputs: {json.dumps(outputs, indent=2)}")
            if error:
                logger.debug(f"Error: {error}")

        def on_workflow_complete(execution_id, workflow_id, outputs):
            logger.debug(f"\n=== Completed workflow: {workflow_id} ===")
            logger.debug(f"Outputs: {json.dumps(outputs, indent=2)}")

        self.register_callback("workflow_start", on_workflow_start)
        self.register_callback("step_start", on_step_start)
        self.register_callback("step_complete", on_step_complete)
        self.register_callback("workflow_complete", on_workflow_complete)

        execution_id = await self.start_workflow(workflow_id, inputs, runtime_params)

        while True:
            result = await self.execute_next_step(execution_id)

            if result.get("status") in [WorkflowExecutionStatus.WORKFLOW_COMPLETE, WorkflowExecutionStatus.ERROR]:
                # Get the execution state to access step outputs
                state = self.execution_states[execution_id]

                # Convert the dictionary result to a WorkflowExecutionResult object
                execution_result = WorkflowExecutionResult(
                    status=result["status"],
                    workflow_id=result.get("workflow_id", workflow_id),
                    outputs=result.get("outputs", {}),
                    step_outputs=state.step_outputs if state.step_outputs else None,
                    inputs=inputs,
                    error=result.get("error")
                )
                return execution_result

    async def execute_next_step(self, execution_id: str) -> dict:
        """
        Execute the next step in the workflow

        Args:
            execution_id: ID of the workflow execution

        Returns:
            WorkflowExecutionResult: Result of the step execution
        """
        if execution_id not in self.execution_states:
            raise ValueError(f"Execution {execution_id} not found")

        state = self.execution_states[execution_id]
        workflow_id = state.workflow_id

        # Find the workflow definition
        workflow = None
        for wf in self.arazzo_doc.get("workflows", []):
            if wf.get("workflowId") == workflow_id:
                workflow = wf
                break

        if not workflow:
            raise ValueError(f"Workflow {workflow_id} not found in Arazzo document")

        # Determine the next step to execute
        steps = workflow.get("steps", [])
        next_step = None
        next_step_idx = 0

        if state.current_step_id is None:
            # First step in the workflow
            if steps:
                next_step = steps[0]
        else:
            # Find the current step index
            current_idx = None
            for idx, step in enumerate(steps):
                if step.get("stepId") == state.current_step_id:
                    current_idx = idx
                    break

            if current_idx is not None and current_idx + 1 < len(steps):
                next_step = steps[current_idx + 1]
                next_step_idx = current_idx + 1

        if not next_step:
            # No more steps to execute, workflow is complete
            self._trigger_event(
                "workflow_complete",
                execution_id=execution_id,
                workflow_id=workflow_id,
                outputs=state.workflow_outputs,
            )
            return {
                "status": WorkflowExecutionStatus.WORKFLOW_COMPLETE,
                "workflow_id": workflow_id,
                "outputs": state.workflow_outputs,
            }

        # Execute the next step
        step_id = next_step.get("stepId")
        state.current_step_id = step_id
        state.status[step_id] = StepStatus.RUNNING

        # Dump state before executing the step for debugging
        logger.info(f"===== EXECUTING STEP: {step_id} =====")
        dump_state(state)

        # Trigger step_start event
        self._trigger_event(
            "step_start", execution_id=execution_id, workflow_id=workflow_id, step_id=step_id
        )

        # Execute the step
        try:
            if "workflowId" in next_step:
                # Handle nested workflow execution
                step_result = await self._execute_nested_workflow(next_step, state)
            else:
                # Execute operation step
                step_result = await self.step_executor.execute_step(next_step, state)

            success = step_result.get("success", False)

            # Update step status
            state.status[step_id] = StepStatus.SUCCESS if success else StepStatus.FAILURE

            # Store step outputs
            state.step_outputs[step_id] = step_result.get("outputs", {})

            # Check if we need to update workflow outputs
            if "outputs" in workflow:
                workflow_outputs = workflow.get("outputs", {})
                for output_name, output_expr in workflow_outputs.items():
                    # Evaluate the output expression
                    value = ExpressionEvaluator.evaluate_expression(
                        output_expr, state, self.source_descriptions
                    )
                    state.workflow_outputs[output_name] = value

            # Determine next action
            next_action = self.step_executor.determine_next_action(next_step, success, state)

            # Trigger step_complete event
            self._trigger_event(
                "step_complete",
                execution_id=execution_id,
                workflow_id=workflow_id,
                step_id=step_id,
                success=success,
                outputs=step_result.get("outputs", {}),
            )

            # Handle the action
            if next_action["type"] == ActionType.END:
                # Check if there's a failure flag from the step
                if not success:
                    # End the workflow with failure
                    self._trigger_event(
                        "workflow_error",
                        execution_id=execution_id,
                        workflow_id=workflow_id,
                        step_id=step_id,
                        error="Step failed success criteria",
                        outputs=state.workflow_outputs,
                    )
                    return {
                        "status": WorkflowExecutionStatus.ERROR,
                        "workflow_id": workflow_id,
                        "step_id": step_id,
                        "error": "Step failed success criteria",
                        "outputs": state.workflow_outputs,
                    }
                else:
                    # End the workflow successfully
                    self._trigger_event(
                        "workflow_complete",
                        execution_id=execution_id,
                        workflow_id=workflow_id,
                        outputs=state.workflow_outputs,
                    )
                    return {
                        "status": WorkflowExecutionStatus.WORKFLOW_COMPLETE,
                        "workflow_id": workflow_id,
                        "outputs": state.workflow_outputs,
                    }
            elif next_action["type"] == ActionType.GOTO:
                # Go to another step or workflow
                if "workflow_id" in next_action:
                    # Start a new workflow
                    new_execution_id = await self.start_workflow(
                        next_action["workflow_id"], next_action.get("inputs", {})
                    )
                    return {
                        "status": WorkflowExecutionStatus.GOTO_WORKFLOW,
                        "workflow_id": next_action["workflow_id"],
                        "execution_id": new_execution_id,
                    }
                elif "step_id" in next_action:
                    # Go to a specific step in the current workflow
                    # Find the step index
                    for idx, step in enumerate(steps):
                        if step.get("stepId") == next_action["step_id"]:
                            next_step_idx = idx
                            break

                    # Update current step
                    state.current_step_id = steps[next_step_idx].get("stepId")
                    return {"status": WorkflowExecutionStatus.GOTO_STEP, "step_id": state.current_step_id}
            elif next_action["type"] == ActionType.RETRY:
                # Retry the current step
                # We don't change the step_id so it will retry on next execution
                state.status[step_id] = StepStatus.PENDING

                # If there's a delay, we should return that information
                retry_delay = next_action.get("retry_after", 0)
                return {"status": WorkflowExecutionStatus.RETRY, "step_id": step_id, "retry_after": retry_delay}

            # Default: continue to next step
            return {
                "status": WorkflowExecutionStatus.STEP_COMPLETE,
                "step_id": step_id,
                "success": success,
                "outputs": step_result.get("outputs", {}),
            }

        except Exception as e:
            logger.error(f"Error executing step {step_id}: {e}")
            state.status[step_id] = StepStatus.FAILURE

            # Trigger step_complete event with failure
            self._trigger_event(
                "step_complete",
                execution_id=execution_id,
                workflow_id=workflow_id,
                step_id=step_id,
                success=False,
                error=str(e),
            )

            return {"status": WorkflowExecutionStatus.STEP_ERROR, "step_id": step_id, "error": str(e)}

    async def _execute_nested_workflow(self, step: dict, state: ExecutionState) -> dict:
        """Execute a nested workflow"""
        workflow_id = step.get("workflowId")

        # Prepare inputs for the nested workflow
        workflow_inputs = {}

        logger.info(f"Preparing inputs for nested workflow: {workflow_id}")

        for param in step.get("parameters", []):
            name = param.get("name")
            value = param.get("value")
            original_value = value

            # Process the value to resolve any expressions
            if isinstance(value, str):
                if value.startswith("$"):
                    # Direct expression
                    value = ExpressionEvaluator.evaluate_expression(
                        value, state, self.source_descriptions
                    )
                elif "{" in value and "}" in value:
                    # Template with expressions
                    import re

                    def replace_expr(match):
                        expr = match.group(1)
                        eval_value = ExpressionEvaluator.evaluate_expression(
                            expr, state, self.source_descriptions
                        )
                        return "" if eval_value is None else str(eval_value)

                    value = re.sub(r"\{([^}]+)\}", replace_expr, value)
            elif isinstance(value, dict):
                value = ExpressionEvaluator.process_object_expressions(
                    value, state, self.source_descriptions
                )
            elif isinstance(value, list):
                value = ExpressionEvaluator.process_array_expressions(
                    value, state, self.source_descriptions
                )

            logger.info(f"  Parameter: {name}, Original: {original_value}, Evaluated: {value}")
            workflow_inputs[name] = value

        # Start the nested workflow
        execution_id = await self.start_workflow(workflow_id, workflow_inputs)

        # Execute the nested workflow until completion
        while True:
            result = await self.execute_next_step(execution_id)
            if result.get("status") in [WorkflowExecutionStatus.WORKFLOW_COMPLETE, WorkflowExecutionStatus.ERROR]:
                break

        # Get the nested workflow outputs
        nested_state = self.execution_states.get(execution_id)
        if not nested_state:
            raise ValueError(f"Nested workflow execution state not found: {execution_id}")

        logger.info(f"Nested workflow outputs: {nested_state.workflow_outputs}")

        # Check if all steps succeeded
        all_success = True
        for step_id, step_status in nested_state.status.items():
            if step_status == StepStatus.FAILURE:
                all_success = False
                logger.warning(f"Nested workflow step failed: {step_id}")
                break

        return {"success": all_success, "outputs": nested_state.workflow_outputs}

    async def execute_operation(
        self,
        inputs: dict[str, Any],
        operation_id: str | None = None,
        operation_path: str | None = None,
        runtime_params: RuntimeParams | None = None,
    ) -> dict:
        """
        Execute a single API operation directly, outside of a workflow context.

        This is the public entry point for direct operation execution.

        Args:
            inputs: Input parameters for the operation.
            operation_id: The operationId of the operation to execute.
            operation_path: The path and method (e.g., 'GET /users/{userId}') of the operation.
                          Provide either operation_id or operation_path, not both.
            runtime_params: Optional runtime parameters for execution (e.g., server variables).

        Returns:
            A dictionary containing the response status_code, headers, and body.
            Example: {'status_code': 200, 'headers': {...}, 'body': ...}

        Raises:
            ValueError: If neither or both operation_id and operation_path are provided,
                        or if the operation cannot be found, or parameters are invalid.
            requests.exceptions.HTTPError: If the API call results in an HTTP error status (4xx or 5xx).
            Exception: For other underlying execution errors.
        """
        # Initial validation duplicated here for clarity at the public API boundary
        if not operation_id and not operation_path:
            raise ValueError("Either operation_id or operation_path must be provided.")
        if operation_id and operation_path:
            raise ValueError("Provide either operation_id or operation_path, not both.")

        log_identifier = f"ID='{operation_id}'" if operation_id else f"Path='{operation_path}'"
        logger.debug(f"OAKRunner: Received request to execute operation directly: {log_identifier}")

        try:
            # Delegate to StepExecutor's implementation
            result = await self.step_executor.execute_operation(
                inputs=inputs,
                operation_id=operation_id,
                operation_path=operation_path,
                runtime_params=runtime_params,
            )
            logger.info(f"OAKRunner: Direct operation execution finished for {log_identifier}")
            return result
        except (ValueError,) as e:
            # Re-raise known error types directly
            logger.error(f"OAKRunner: Error executing operation {log_identifier}: {e}")
            raise e
        except Exception as e:
            # Catch unexpected errors
            logger.exception(f"OAKRunner: Unexpected error executing operation {log_identifier}: {e}")
            # Wrap or re-raise depending on desired error handling strategy
            raise RuntimeError(f"Unexpected error during operation execution: {e}") from e

    # Sync wrapper methods for backward compatibility
    def start_workflow_sync(self, workflow_id: str, inputs: dict[str, Any] | None = None, runtime_params: RuntimeParams | None = None) -> str:
        """Synchronous wrapper for start_workflow"""
        return asyncio.run(self.start_workflow(workflow_id, inputs, runtime_params))

    def execute_workflow_sync(
        self,
        workflow_id: str,
        inputs: dict[str, Any] = None,
        runtime_params: RuntimeParams | None = None
    ) -> WorkflowExecutionResult:
        """Synchronous wrapper for execute_workflow"""
        return asyncio.run(self.execute_workflow(workflow_id, inputs, runtime_params))

    def execute_next_step_sync(self, execution_id: str) -> dict:
        """Synchronous wrapper for execute_next_step"""
        return asyncio.run(self.execute_next_step(execution_id))

    def execute_operation_sync(
        self,
        inputs: dict[str, Any],
        operation_id: str | None = None,
        operation_path: str | None = None,
        runtime_params: RuntimeParams | None = None,
    ) -> dict:
        """Synchronous wrapper for execute_operation"""
        return asyncio.run(self.execute_operation(inputs, operation_id, operation_path, runtime_params))

    # Original sync methods maintained for compatibility
    def start_workflow(self, workflow_id: str, inputs: dict[str, Any] | None = None, runtime_params: RuntimeParams | None = None) -> str:
        """Synchronous version that wraps the async implementation"""
        return self.start_workflow_sync(workflow_id, inputs, runtime_params)

    def execute_workflow(
        self,
        workflow_id: str,
        inputs: dict[str, Any] = None,
        runtime_params: RuntimeParams | None = None
    ) -> WorkflowExecutionResult:
        """Synchronous version that wraps the async implementation"""
        return self.execute_workflow_sync(workflow_id, inputs, runtime_params)

    def execute_next_step(self, execution_id: str) -> dict:
        """Synchronous version that wraps the async implementation"""
        return self.execute_next_step_sync(execution_id)

    def execute_operation(
        self,
        inputs: dict[str, Any],
        operation_id: str | None = None,
        operation_path: str | None = None,
        runtime_params: RuntimeParams | None = None,
    ) -> dict:
        """Synchronous version that wraps the async implementation"""
        return self.execute_operation_sync(inputs, operation_id, operation_path, runtime_params)

    @deprecated("Use OAKRunner.generate_env_mappings instead. Will drop support in a future release.")
    def get_env_mappings(self) -> dict[str, Any]:
        """
        DEPRECATED: Use OAKRunner.generate_env_mappings instead.
        Returns the environment variable mappings for both authentication and server variables.
       
        Returns:
            Dictionary containing:
            - 'auth': Environment variable mappings for authentication
            - 'servers': Environment variable mappings for server URLs (only included if server variables exist)
        """
        # Get authentication environment mappings (old way)
        try:
            auth_mappings = self.auth_provider.env_mappings
        except AttributeError:
            auth_mappings = {}

        # Get authentication environment mappings via the EnvironmentVariableFetchStrategy
        try:
            auth_mappings = self.auth_provider.strategy._env_mapping
        except AttributeError:
            auth_mappings = {}

        result = {"auth": auth_mappings}

        # Get server variable environment mappings
        server_mappings = self.step_executor.server_processor.get_env_mappings()
        # Only include server mappings if they exist
        if server_mappings:
            result["servers"] = server_mappings

        return result

    @staticmethod
    def generate_env_mappings(
        arazzo_docs: list["ArazzoDoc"] | None = None,
        source_descriptions: dict[str, "OpenAPIDoc"] = None,
    ) -> dict:
        """
        Static method to return the environment variable mappings for both authentication and server variables.

        Args:
            arazzo_docs: List of parsed Arazzo documents (optional)
            source_descriptions: Dictionary of source names to OpenAPI spec dicts.

        Returns:
            Dictionary containing:
            - 'auth': Environment variable mappings for authentication
            - 'servers': Environment variable mappings for server URLs (only included if server variables exist)
        """
        auth_processor = AuthProcessor()
        auth_config = auth_processor.process_api_auth(
            openapi_specs=source_descriptions,
            arazzo_specs=arazzo_docs or [],
        )
        auth_env_mappings = auth_config.get("env_mappings", {})

        server_processor = ServerProcessor(source_descriptions or {})
        server_env_mappings = server_processor.get_env_mappings()
        result = {"auth": auth_env_mappings}
        if server_env_mappings:
            result["servers"] = server_env_mappings
        return result