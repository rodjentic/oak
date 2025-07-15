# tests/base_test.py
"""
Base test class for OAK Runner tests with async support

This module provides base test functionality for testing OAK Runner workflows and operations.
"""

import asyncio
import json
import os
import tempfile
import unittest
from typing import Any, Dict, List, Optional, Union
from unittest.mock import Mock

import httpx
import pytest
import yaml

from oak_runner import OAKRunner, WorkflowExecutionResult, WorkflowExecutionStatus


class MockAsyncHTTPClient:
    """Mock async HTTP client for testing"""

    def __init__(self):
        self.responses = {}
        self.requests = []
        self.call_count = 0

    def add_static_response(
        self, method: str, url_pattern: str, status_code: int = 200, json_data: Any = None, text_data: str = None, headers: Dict[str, str] = None
    ):
        """Add a static response for a URL pattern"""
        key = (method.lower(), url_pattern)
        response_data = {
            "status_code": status_code,
            "json_data": json_data,
            "text_data": text_data,
            "headers": headers or {},
        }
        self.responses[key] = response_data

    async def request(self, method: str, url: str, **kwargs) -> "MockResponse":
        """Mock request method"""
        self.call_count += 1
        
        # Record the request
        request_record = {
            "method": method.lower(),
            "url": url,
            "kwargs": kwargs,
            "call_number": self.call_count,
        }
        self.requests.append(request_record)

        # Find matching response
        for (response_method, url_pattern), response_data in self.responses.items():
            if method.lower() == response_method and url_pattern in url:
                return MockResponse(
                    status_code=response_data["status_code"],
                    json_data=response_data["json_data"],
                    text_data=response_data["text_data"],
                    headers=response_data["headers"],
                )

        # Default response if no match
        return MockResponse(status_code=404, json_data={"error": "Not found"})

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class MockResponse:
    """Mock HTTP response"""

    def __init__(self, status_code: int = 200, json_data: Any = None, text_data: str = None, headers: Dict[str, str] = None):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text_data or (json.dumps(json_data) if json_data else "")
        self.headers = headers or {}
        self.content = self.text.encode() if isinstance(self.text, str) else self.text or b""

    def json(self):
        if self._json_data is not None:
            return self._json_data
        if self.text:
            try:
                return json.loads(self.text)
            except json.JSONDecodeError:
                raise ValueError("No JSON data available")
        raise ValueError("No JSON data available")


class ArazzoTestCase(unittest.TestCase):
    """Base test case for OAK Runner tests with async support"""

    def setUp(self):
        """Set up test fixtures"""
        # Create temporary directory
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = self.temp_dir.name

        # Initialize mock HTTP client
        self.http_client = MockAsyncHTTPClient()

        # Track created files for cleanup
        self.created_files = []

    def tearDown(self):
        """Clean up test fixtures"""
        self.temp_dir.cleanup()

    def create_openapi_spec(self, spec_dict: Dict[str, Any], filename: str = "test_openapi") -> str:
        """Create an OpenAPI spec file and return its path"""
        filepath = os.path.join(self.temp_path, f"{filename}.yaml")
        with open(filepath, "w") as f:
            yaml.dump(spec_dict, f)
        self.created_files.append(filepath)
        return filepath

    def create_arazzo_spec(self, spec_dict: Dict[str, Any], filename: str = "test_arazzo") -> str:
        """Create an Arazzo spec file and return its path"""
        filepath = os.path.join(self.temp_path, f"{filename}.yaml")
        with open(filepath, "w") as f:
            yaml.dump(spec_dict, f)
        self.created_files.append(filepath)
        return filepath

    def load_test_openapi_spec(self, openapi_path: str) -> str:
        """Load OpenAPI spec for testing - returns the spec name for reference"""
        # Extract filename without extension as spec name
        spec_name = os.path.splitext(os.path.basename(openapi_path))[0]
        return spec_name

    def create_oak_runner(
        self, arazzo_doc_path: str, source_descriptions: Dict[str, Any]
    ) -> OAKRunner:
        """Create an OAK Runner instance for testing"""
        # Load the Arazzo document
        with open(arazzo_doc_path, "r") as f:
            arazzo_doc = yaml.safe_load(f)

        # Create runner with mock HTTP client
        runner = OAKRunner(
            arazzo_doc=arazzo_doc,
            source_descriptions=source_descriptions,
            http_client=self.http_client,
        )
        return runner

    async def execute_workflow_async(
        self,
        runner: OAKRunner,
        workflow_id: str,
        inputs: Dict[str, Any],
        expect_success: bool = True,
    ) -> WorkflowExecutionResult:
        """Execute a workflow asynchronously with enhanced error handling"""
        try:
            result = await runner.execute_workflow_async(workflow_id, inputs)

            if expect_success:
                self.assertEqual(
                    result.status,
                    WorkflowExecutionStatus.WORKFLOW_COMPLETE,
                    f"Expected workflow to complete successfully, but got {result.status}. Error: {result.error}",
                )
            else:
                self.assertEqual(
                    result.status,
                    WorkflowExecutionStatus.ERROR,
                    f"Expected workflow to fail, but got {result.status}",
                )

            return result

        except Exception as e:
            if expect_success:
                self.fail(f"Workflow execution failed unexpectedly: {e}")
            else:
                # If we expected failure and got an exception, that's okay
                # Create a mock result to represent the failure
                return WorkflowExecutionResult(
                    status=WorkflowExecutionStatus.ERROR,
                    workflow_id=workflow_id,
                    outputs={},
                    error=str(e),
                )

    def execute_workflow(
        self,
        runner: OAKRunner,
        workflow_id: str,
        inputs: Dict[str, Any],
        expect_success: bool = True,
    ) -> WorkflowExecutionResult:
        """Execute a workflow synchronously (wrapper around async method)"""
        return asyncio.run(self.execute_workflow_async(runner, workflow_id, inputs, expect_success))

    async def execute_operation_async(
        self,
        runner: OAKRunner,
        operation_id: Optional[str] = None,
        operation_path: Optional[str] = None,
        inputs: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """Execute a single operation asynchronously"""
        if inputs is None:
            inputs = {}

        return await runner.execute_operation_async(
            inputs=inputs, operation_id=operation_id, operation_path=operation_path
        )

    def execute_operation(
        self,
        runner: OAKRunner,
        operation_id: Optional[str] = None,
        operation_path: Optional[str] = None,
        inputs: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """Execute a single operation synchronously (wrapper around async method)"""
        return asyncio.run(self.execute_operation_async(runner, operation_id, operation_path, inputs))

    def validate_api_calls(self, expected_call_count: Optional[int] = None):
        """Validate that the expected number of API calls were made"""
        actual_call_count = len(self.http_client.requests)

        if expected_call_count is not None:
            self.assertEqual(
                actual_call_count,
                expected_call_count,
                f"Expected {expected_call_count} API calls, but {actual_call_count} were made",
            )

    def get_api_call(self, call_index: int) -> Dict[str, Any]:
        """Get details of a specific API call by index"""
        if call_index >= len(self.http_client.requests):
            self.fail(f"No API call at index {call_index}. Only {len(self.http_client.requests)} calls were made.")

        return self.http_client.requests[call_index]

    def validate_api_call(
        self,
        call_index: int,
        expected_method: str,
        expected_url_pattern: str,
        expected_params: Optional[Dict[str, Any]] = None,
        expected_headers: Optional[Dict[str, str]] = None,
        expected_json: Optional[Dict[str, Any]] = None,
    ):
        """Validate the details of a specific API call"""
        call = self.get_api_call(call_index)

        # Validate method
        self.assertEqual(
            call["method"].lower(),
            expected_method.lower(),
            f"Call {call_index}: Expected method {expected_method}, got {call['method']}",
        )

        # Validate URL contains expected pattern
        self.assertIn(
            expected_url_pattern,
            call["url"],
            f"Call {call_index}: Expected URL to contain {expected_url_pattern}, got {call['url']}",
        )

        # Validate parameters if provided
        if expected_params:
            call_params = call["kwargs"].get("params", {})
            for key, value in expected_params.items():
                self.assertIn(
                    key,
                    call_params,
                    f"Call {call_index}: Expected parameter {key} not found in call params",
                )
                self.assertEqual(
                    call_params[key],
                    value,
                    f"Call {call_index}: Expected parameter {key}={value}, got {call_params[key]}",
                )

        # Validate headers if provided
        if expected_headers:
            call_headers = call["kwargs"].get("headers", {})
            for key, value in expected_headers.items():
                self.assertIn(
                    key,
                    call_headers,
                    f"Call {call_index}: Expected header {key} not found in call headers",
                )
                self.assertEqual(
                    call_headers[key],
                    value,
                    f"Call {call_index}: Expected header {key}={value}, got {call_headers[key]}",
                )

        # Validate JSON body if provided
        if expected_json:
            call_json = call["kwargs"].get("json", {})
            for key, value in expected_json.items():
                self.assertIn(
                    key, call_json, f"Call {call_index}: Expected JSON key {key} not found in call body"
                )
                self.assertEqual(
                    call_json[key],
                    value,
                    f"Call {call_index}: Expected JSON {key}={value}, got {call_json[key]}",
                )

    def print_api_call_summary(self):
        """Print a summary of all API calls made during the test"""
        print(f"\n=== API Call Summary ({len(self.http_client.requests)} calls) ===")
        for i, call in enumerate(self.http_client.requests):
            print(f"Call {i + 1}: {call['method'].upper()} {call['url']}")
            if call["kwargs"].get("params"):
                print(f"  Params: {call['kwargs']['params']}")
            if call["kwargs"].get("headers"):
                print(f"  Headers: {call['kwargs']['headers']}")
            if call["kwargs"].get("json"):
                print(f"  JSON: {call['kwargs']['json']}")
            if call["kwargs"].get("data"):
                print(f"  Data: {call['kwargs']['data']}")
        print("=" * 50)

    def assert_step_outputs_contain(self, result: WorkflowExecutionResult, step_id: str, expected_outputs: Dict[str, Any]):
        """Assert that a step's outputs contain the expected values"""
        self.assertIsNotNone(result.step_outputs, "Workflow result should have step outputs")
        self.assertIn(step_id, result.step_outputs, f"Step {step_id} should be in step outputs")

        step_outputs = result.step_outputs[step_id]
        for key, expected_value in expected_outputs.items():
            self.assertIn(key, step_outputs, f"Step {step_id} outputs should contain key {key}")
            self.assertEqual(
                step_outputs[key],
                expected_value,
                f"Step {step_id} output {key} should equal {expected_value}, got {step_outputs[key]}",
            )

    def assert_workflow_outputs_contain(self, result: WorkflowExecutionResult, expected_outputs: Dict[str, Any]):
        """Assert that the workflow outputs contain the expected values"""
        for key, expected_value in expected_outputs.items():
            self.assertIn(key, result.outputs, f"Workflow outputs should contain key {key}")
            self.assertEqual(
                result.outputs[key],
                expected_value,
                f"Workflow output {key} should equal {expected_value}, got {result.outputs[key]}",
            )


class AsyncArazzoTestCase(ArazzoTestCase):
    """Async version of ArazzoTestCase for use with pytest-asyncio"""

    async def asyncSetUp(self):
        """Async setup method"""
        self.setUp()

    async def asyncTearDown(self):
        """Async teardown method"""
        self.tearDown()


# Pytest fixtures for async testing
@pytest.fixture
async def async_test_case():
    """Fixture to provide an async test case instance"""
    test_case = AsyncArazzoTestCase()
    await test_case.asyncSetUp()
    yield test_case
    await test_case.asyncTearDown()


@pytest.fixture
def mock_http_client():
    """Fixture to provide a mock HTTP client"""
    return MockAsyncHTTPClient()