# tests/test_async_framework_demo.py
"""
Demonstration of the OAK Runner Async Test Framework

This module provides example tests that demonstrate how to use the async Arazzo testing framework.
"""

import pytest

from oak_runner import WorkflowExecutionStatus

from .base_test import AsyncArazzoTestCase


class TestAsyncArazzoFramework:
    """Test cases demonstrating the async Arazzo test framework"""

    @pytest.mark.asyncio
    async def test_basic_async_workflow(self, async_test_case: AsyncArazzoTestCase):
        """Test a simple workflow with a login and data fetch operation using async"""
        # Create an OpenAPI spec
        openapi_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "description": "API for testing", "version": "1.0.0"},
            "servers": [{"url": "https://api.example.com/v1"}],
            "paths": {
                "/login": {
                    "post": {
                        "operationId": "loginUser",
                        "summary": "Log in a user",
                        "parameters": [],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "username": {"type": "string"},
                                            "password": {"type": "string"},
                                        },
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "Success",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "token": {"type": "string"},
                                                "user_id": {"type": "string"},
                                            },
                                        }
                                    }
                                },
                            },
                            "401": {
                                "description": "Unauthorized",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {"error": {"type": "string"}},
                                        }
                                    }
                                },
                            },
                        },
                    }
                },
                "/data": {
                    "get": {
                        "operationId": "getData",
                        "summary": "Get data",
                        "parameters": [
                            {"name": "filter", "in": "query", "schema": {"type": "string"}}
                        ],
                        "responses": {
                            "200": {
                                "description": "Success",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "items": {
                                                    "type": "array",
                                                    "items": {
                                                        "type": "object",
                                                        "properties": {
                                                            "id": {"type": "integer"},
                                                            "name": {"type": "string"},
                                                            "created_at": {
                                                                "type": "string",
                                                                "format": "date-time",
                                                            },
                                                        },
                                                    },
                                                },
                                                "total": {"type": "integer"},
                                            },
                                        }
                                    }
                                },
                            },
                            "401": {
                                "description": "Unauthorized",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {"error": {"type": "string"}},
                                        }
                                    }
                                },
                            },
                        },
                    }
                },
            },
        }

        openapi_path = async_test_case.create_openapi_spec(openapi_spec, "basic_api")

        # Create an Arazzo workflow spec
        arazzo_spec = {
            "arazzo": "1.0.0",
            "info": {
                "title": "Basic Workflow",
                "description": "A simple workflow for testing",
                "version": "1.0.0",
            },
            "sourceDescriptions": [{"name": "testApi", "url": openapi_path, "type": "openapi"}],
            "workflows": [
                {
                    "workflowId": "basicWorkflow",
                    "summary": "Basic workflow",
                    "description": "A basic workflow that logs in and fetches data",
                    "inputs": {
                        "type": "object",
                        "properties": {
                            "username": {"type": "string"},
                            "password": {"type": "string"},
                            "filter": {"type": "string"},
                        },
                    },
                    "steps": [
                        {
                            "stepId": "loginStep",
                            "description": "Login step",
                            "operationId": "loginUser",
                            "requestBody": {
                                "contentType": "application/json",
                                "payload": {
                                    "username": "$inputs.username",
                                    "password": "$inputs.password",
                                },
                            },
                            "successCriteria": [{"condition": "$statusCode == 200"}],
                            "outputs": {
                                "token": "$response.body.token",
                                "userId": "$response.body.user_id",
                            },
                        },
                        {
                            "stepId": "getDataStep",
                            "description": "Get data step",
                            "operationId": "getData",
                            "parameters": [
                                {"name": "filter", "in": "query", "value": "$inputs.filter"},
                                {
                                    "name": "Authorization",
                                    "in": "header",
                                    "value": "Bearer $steps.loginStep.token",
                                },
                            ],
                            "successCriteria": [{"condition": "$statusCode == 200"}],
                            "outputs": {
                                "items": "$response.body.items",
                                "total": "$response.body.total",
                            },
                        },
                    ],
                    "outputs": {
                        "data": "$steps.getDataStep.items",
                        "dataCount": "$steps.getDataStep.total",
                        "userId": "$steps.loginStep.userId",
                    },
                }
            ],
        }

        arazzo_doc = async_test_case.create_arazzo_spec(arazzo_spec, "basic_workflow")

        # Configure mock responses
        async_test_case.http_client.add_static_response(
            method="post",
            url_pattern="https://api.example.com/v1/login",
            status_code=200,
            json_data={"token": "token-testuser-123", "user_id": "user-testuser-456"},
        )

        async_test_case.http_client.add_static_response(
            method="get",
            url_pattern="https://api.example.com/v1/data",
            status_code=200,
            json_data={
                "items": [
                    {"id": 1, "name": "Item 1", "created_at": "2023-01-01T00:00:00Z"},
                    {"id": 2, "name": "Item 2", "created_at": "2023-01-02T00:00:00Z"},
                ],
                "total": 2,
            },
        )

        runner = async_test_case.create_oak_runner(arazzo_doc, {"testApi": openapi_spec})

        # Execute the workflow asynchronously
        inputs = {"username": "testuser", "password": "password123", "filter": "test"}

        result = await async_test_case.execute_workflow_async(runner, "basicWorkflow", inputs)

        # Validate the workflow executed successfully
        assert result.status == WorkflowExecutionStatus.WORKFLOW_COMPLETE

        # Validate the API calls
        async_test_case.validate_api_calls(expected_call_count=2)

        # Print the API call summary for debugging
        async_test_case.print_api_call_summary()

    @pytest.mark.asyncio
    async def test_async_error_handling(self, async_test_case: AsyncArazzoTestCase):
        """Test workflow error handling with a failing API call using async"""
        # Create an OpenAPI spec
        openapi_spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "Error Test API",
                "description": "API for testing error handling",
                "version": "1.0.0",
            },
            "servers": [{"url": "https://api.example.com/v1"}],
            "paths": {
                "/login": {
                    "post": {
                        "operationId": "loginUser",
                        "summary": "Log in a user",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "username": {"type": "string"},
                                            "password": {"type": "string"},
                                        },
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "Success",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {"token": {"type": "string"}},
                                        }
                                    }
                                },
                            },
                            "401": {
                                "description": "Unauthorized",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {"error": {"type": "string"}},
                                        }
                                    }
                                },
                            },
                        },
                    }
                }
            },
        }

        openapi_path = async_test_case.create_openapi_spec(openapi_spec, "error_api")

        # Create an Arazzo workflow spec
        arazzo_spec = {
            "arazzo": "1.0.0",
            "info": {
                "title": "Error Handling Workflow",
                "description": "A workflow for testing error handling",
                "version": "1.0.0",
            },
            "sourceDescriptions": [{"name": "errorApi", "url": openapi_path, "type": "openapi"}],
            "workflows": [
                {
                    "workflowId": "errorHandlingWorkflow",
                    "summary": "Error handling workflow",
                    "description": "A workflow that tests error handling",
                    "inputs": {
                        "type": "object",
                        "properties": {
                            "username": {"type": "string"},
                            "password": {"type": "string"},
                        },
                    },
                    "steps": [
                        {
                            "stepId": "loginStep",
                            "description": "Login step",
                            "operationId": "loginUser",
                            "requestBody": {
                                "contentType": "application/json",
                                "payload": {
                                    "username": "$inputs.username",
                                    "password": "$inputs.password",
                                },
                            },
                            "successCriteria": [{"condition": "$statusCode == 200"}],
                            "outputs": {"token": "$response.body.token"},
                        }
                    ],
                    "outputs": {"token": "$steps.loginStep.outputs.token"},
                }
            ],
        }

        arazzo_doc = async_test_case.create_arazzo_spec(arazzo_spec, "error_workflow")

        # Configure mock for failed login
        async_test_case.http_client.add_static_response(
            method="post",
            url_pattern="https://api.example.com/v1/login",
            status_code=401,
            json_data={"error": "Invalid credentials"},
        )

        # Create the OAK Runner
        runner = async_test_case.create_oak_runner(arazzo_doc, {"testApi": openapi_spec})

        # Execute the workflow, expecting failure
        inputs = {"username": "testuser", "password": "password123"}

        # Use our async execute_workflow method with expect_success=False
        result = await async_test_case.execute_workflow_async(
            runner, "errorHandlingWorkflow", inputs, expect_success=False
        )

        # Validate the API calls
        async_test_case.validate_api_calls(expected_call_count=1)

        # Check that we got the expected status
        assert result.status == WorkflowExecutionStatus.ERROR

        # The output token should not exist or be None since the step failed
        assert (
            "token" not in result.outputs or result.outputs["token"] is None
        ), f"Expected token to be None or missing, but got {result.outputs.get('token', 'missing')}"

        # Print the API call summary for debugging
        async_test_case.print_api_call_summary()

    @pytest.mark.asyncio
    async def test_async_operation_execution(self, async_test_case: AsyncArazzoTestCase):
        """Test direct operation execution using async"""
        # Create a simple OpenAPI spec
        openapi_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Direct Operation API", "version": "1.0.0"},
            "servers": [{"url": "https://api.example.com/v1"}],
            "paths": {
                "/users/{userId}": {
                    "get": {
                        "operationId": "getUser",
                        "summary": "Get user by ID",
                        "parameters": [
                            {"name": "userId", "in": "path", "required": True, "schema": {"type": "string"}}
                        ],
                        "responses": {
                            "200": {
                                "description": "User found",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "id": {"type": "string"},
                                                "name": {"type": "string"},
                                                "email": {"type": "string"},
                                            },
                                        }
                                    }
                                },
                            }
                        },
                    }
                }
            },
        }

        # Create runner from OpenAPI spec directly
        openapi_path = async_test_case.create_openapi_spec(openapi_spec, "direct_api")
        runner = OAKRunner.from_openapi_path(openapi_path)
        
        # Replace the default HTTP client with our mock
        runner.step_executor.http_client.http_client = async_test_case.http_client

        # Configure mock response
        async_test_case.http_client.add_static_response(
            method="get",
            url_pattern="https://api.example.com/v1/users/123",
            status_code=200,
            json_data={"id": "123", "name": "John Doe", "email": "john@example.com"},
        )

        # Execute operation directly using async
        inputs = {"userId": "123"}
        result = await async_test_case.execute_operation_async(
            runner, operation_id="getUser", inputs=inputs
        )

        # Validate response
        assert result["status_code"] == 200
        assert result["body"]["id"] == "123"
        assert result["body"]["name"] == "John Doe"

        # Validate API call was made correctly
        async_test_case.validate_api_calls(expected_call_count=1)
        async_test_case.validate_api_call(
            call_index=0,
            expected_method="get",
            expected_url_pattern="https://api.example.com/v1/users/123",
        )