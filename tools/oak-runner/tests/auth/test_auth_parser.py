# tests/auth/test_auth_parser.py
"""Tests for the Arazzo authentication parser."""

import os
import unittest
from typing import Any

import yaml

from oak_runner.auth.auth_parser import (
    AuthLocation,
    AuthRequirement,
    AuthType,
    auth_requirements_to_dict,
    extract_auth_from_arazzo,
    extract_auth_from_openapi,
)


class TestAuthParser(unittest.TestCase):
    """Test authentication parser functionality."""

    def setUp(self):
        """Set up test data."""
        # Simple OpenAPI spec with API key auth
        self.openapi_spec_api_key: dict[str, Any] = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "components": {
                "securitySchemes": {
                    "api_key": {
                        "type": "apiKey",
                        "name": "X-API-Key",
                        "in": "header",
                        "description": "API key for authentication",
                    }
                }
            },
            "security": [{"api_key": []}],
        }

        # OpenAPI spec with OAuth2 auth
        self.openapi_spec_oauth2: dict[str, Any] = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "components": {
                "securitySchemes": {
                    "oauth2": {
                        "type": "oauth2",
                        "description": "OAuth2 authentication",
                        "flows": {
                            "implicit": {
                                "authorizationUrl": "https://example.com/auth",
                                "scopes": {
                                    "read:items": "Read access to items",
                                    "write:items": "Write access to items",
                                },
                            }
                        },
                    }
                }
            },
            "security": [{"oauth2": ["read:items"]}],
        }

        # OpenAPI spec with bearer token auth
        self.openapi_spec_bearer: dict[str, Any] = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "description": "Bearer token authentication",
                    }
                }
            },
            "security": [{"bearerAuth": []}],
        }

        # Arazzo workflow with auth parameter
        self.arazzo_spec: dict[str, Any] = {
            "arazzo": "1.0.0",
            "info": {"title": "Test Workflow", "version": "1.0.0"},
            "sourceDescriptions": [{"name": "testApi", "url": "openapi.yaml", "type": "openapi"}],
            "workflows": [
                {
                    "workflowId": "testWorkflow",
                    "steps": [
                        {
                            "stepId": "step1",
                            "operationId": "getItems",
                            "parameters": [
                                {"name": "Authorization", "in": "header", "value": "$inputs.token"}
                            ],
                        }
                    ],
                }
            ],
        }

    def test_extract_auth_from_openapi_api_key(self):
        """Test extracting API key authentication from OpenAPI spec."""
        auth_reqs = extract_auth_from_openapi(self.openapi_spec_api_key)
        # Set source_description_id after extraction
        for req in auth_reqs:
            req.source_description_id = "test_api_key"

        self.assertEqual(len(auth_reqs), 1)
        self.assertEqual(auth_reqs[0].auth_type, AuthType.API_KEY)
        self.assertEqual(auth_reqs[0].name, "X-API-Key")
        self.assertEqual(auth_reqs[0].location, AuthLocation.HEADER)
        self.assertTrue(auth_reqs[0].required)

    def test_extract_auth_from_openapi_oauth2(self):
        """Test extracting OAuth2 authentication from OpenAPI spec."""
        auth_reqs = extract_auth_from_openapi(self.openapi_spec_oauth2)
        # Set source_description_id after extraction
        for req in auth_reqs:
            req.source_description_id = "test_oauth2"

        self.assertEqual(len(auth_reqs), 1)

    def test_extract_auth_from_openapi_bearer(self):
        """Test extracting bearer token authentication from OpenAPI spec."""
        auth_reqs = extract_auth_from_openapi(self.openapi_spec_bearer)
        # Set source_description_id after extraction
        for req in auth_reqs:
            req.source_description_id = "test_bearer"

        self.assertEqual(len(auth_reqs), 1)
        self.assertEqual(auth_reqs[0].auth_type, AuthType.HTTP)
        self.assertEqual(auth_reqs[0].name, "bearerAuth")
        self.assertEqual(auth_reqs[0].schemes, ["bearer"])
        self.assertTrue(auth_reqs[0].required)

    def test_extract_auth_from_arazzo(self):
        """Test extracting authentication from Arazzo workflow."""
        auth_reqs = extract_auth_from_arazzo(self.arazzo_spec)

        self.assertEqual(len(auth_reqs), 1)
        self.assertEqual(auth_reqs[0].auth_type, AuthType.API_KEY)
        self.assertEqual(auth_reqs[0].name, "Authorization")
        self.assertEqual(auth_reqs[0].location, AuthLocation.HEADER)

    def test_extract_auth_requirements_combined(self):
        """Test extracting authentication from both OpenAPI and Arazzo specs."""
        auth_reqs = extract_auth_from_openapi(self.openapi_spec_api_key) + extract_auth_from_arazzo(self.arazzo_spec)

        self.assertEqual(len(auth_reqs), 2)
        auth_types = [req.auth_type for req in auth_reqs]
        self.assertEqual(set(auth_types), {AuthType.API_KEY})

    def test_pet_store_openapi(self):
        """Test with the pet store OpenAPI example from the project."""
        # Point to the fixtures directory
        fixtures_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "tests",
            "fixtures",
            "pet_coupons",
        )

        openapi_path = os.path.join(fixtures_dir, "pet-coupons.openapi.yaml")

        with open(openapi_path) as f:
            openapi_spec = yaml.safe_load(f)

        auth_reqs = extract_auth_from_openapi(openapi_spec)

        self.assertEqual(len(auth_reqs), 2)

        auth_types = [req.auth_type for req in auth_reqs]
        self.assertIn(AuthType.API_KEY, auth_types)
        self.assertIn(AuthType.OAUTH2, auth_types)

        api_key_auth = next(req for req in auth_reqs if req.auth_type == AuthType.API_KEY)
        self.assertEqual(api_key_auth.name, "api_key")
        self.assertEqual(api_key_auth.location, AuthLocation.HEADER)

    def test_extract_auth_from_openapi_with_source_description(self):
        """Test extracting authentication with a custom source description."""
        custom_source = "custom-api-source"
        auth_reqs = extract_auth_from_openapi(self.openapi_spec_api_key)
        for req in auth_reqs:
            req.source_description_id = custom_source

        self.assertEqual(len(auth_reqs), 1)
        self.assertEqual(auth_reqs[0].auth_type, AuthType.API_KEY)
        self.assertEqual(auth_reqs[0].source_description_id, custom_source)
        api_title = self.openapi_spec_api_key.get("info", {}).get("title", "")
        self.assertEqual(auth_reqs[0].api_title, api_title)

        different_source = "different-api-source"
        auth_reqs = extract_auth_from_openapi(self.openapi_spec_api_key)
        for req in auth_reqs:
            req.source_description_id = different_source
        self.assertEqual(auth_reqs[0].source_description_id, different_source)

    def test_auth_requirements_to_dict(self):
        """Test converting auth requirements to dictionaries."""
        api_key_auth = AuthRequirement(
            auth_type=AuthType.API_KEY,
            name="api_key",
            location=AuthLocation.HEADER,
            description="API Key for authentication",
            required=True,
        )

        oauth2_auth = AuthRequirement(
            auth_type=AuthType.OAUTH2,
            name="oauth2",
            description="OAuth2 authentication",
            flow_type="implicit",
            scopes=["read", "write"],
            auth_urls={"authorization": "https://example.com/auth"},
            required=True,
        )

        auth_dicts = auth_requirements_to_dict([api_key_auth, oauth2_auth])

        self.assertEqual(len(auth_dicts), 2)

        api_key_dict = next(d for d in auth_dicts if d["name"] == "api_key")
        self.assertEqual(api_key_dict["type"], "apiKey")
        self.assertEqual(api_key_dict["location"], "header")
        self.assertTrue(api_key_dict["required"])

        oauth2_dict = next(d for d in auth_dicts if d["name"] == "oauth2")
        self.assertEqual(oauth2_dict["type"], "oauth2")
        self.assertEqual(oauth2_dict["flow_type"], "implicit")
        self.assertEqual(oauth2_dict["scopes"], ["read", "write"])
        self.assertEqual(oauth2_dict["auth_urls"], {"authorization": "https://example.com/auth"})

    def test_extract_auth_from_openapi_openid_only(self):
        """Test that OpenID Connect is skipped."""
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test OpenID", "version": "1.0.0"},
            "components": {
                "securitySchemes": {
                    "openId": {
                        "type": "openIdConnect",
                        "openIdConnectUrl": "https://example.com/.well-known/openid-configuration"
                    }
                }
            },
            "security": [{"openId": []}]
        }
        auth_reqs = extract_auth_from_openapi(spec)
        self.assertEqual(len(auth_reqs), 0, "OpenID Connect should be skipped")

    def test_extract_auth_from_openapi_oauth2_mixed_flows(self):
        """Test handling of mixed supported/unsupported OAuth2 flows."""
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test Mixed OAuth Flows", "version": "1.0.0"},
            "components": {
                "securitySchemes": {
                    "mixedOAuth": {
                        "type": "oauth2",
                        "flows": {
                            "implicit": { # Unsupported
                                "authorizationUrl": "https://example.com/auth_implicit",
                                "scopes": {"read": "Read access"}
                            },
                            "clientCredentials": { # Supported
                                "tokenUrl": "https://example.com/token_cc",
                                "scopes": {"internal": "Internal access"}
                            }
                        }
                    }
                }
            },
            "security": [{"mixedOAuth": ["internal"]}]
        }
        auth_reqs = extract_auth_from_openapi(spec)
        self.assertEqual(len(auth_reqs), 2, "All flows should be extracted")
        self.assertEqual(auth_reqs[1].auth_type, AuthType.OAUTH2)
        self.assertEqual(auth_reqs[1].flow_type, "clientCredentials")
        self.assertEqual(auth_reqs[1].scopes, ["internal"])

    def test_extract_auth_from_openapi_mixed_schemes(self):
        """Test handling of mixed supported/unsupported security schemes."""
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test Mixed Schemes", "version": "1.0.0"},
            "components": {
                "securitySchemes": {
                    "apiKeyAuth": { # Supported
                        "type": "apiKey", "name": "X-API-Key", "in": "header"
                    },
                    "bearerAuth": { # Supported
                        "type": "http", "scheme": "bearer"
                    },
                    "oauthImplicit": { # Unsupported
                        "type": "oauth2",
                        "flows": {"implicit": {"authorizationUrl": "https://e.com/auth", "scopes": {"r": "r"}}}
                    },
                    "openIdAuth": { # Unsupported
                        "type": "openIdConnect",
                        "openIdConnectUrl": "https://e.com/.well-known"
                    }
                }
            },
            # Security field might reference a mix, but extraction should only yield supported ones
            "security": [
                {"apiKeyAuth": []},
                {"bearerAuth": []},
                {"oauthImplicit": ["r"]}, 
                {"openIdAuth": []}
            ]
        }
        auth_reqs = extract_auth_from_openapi(spec)
        self.assertEqual(len(auth_reqs), 3, "All schemes must be extracted")
        extracted_types = {req.auth_type for req in auth_reqs}
        self.assertIn(AuthType.API_KEY, extracted_types)
        self.assertIn(AuthType.HTTP, extracted_types)
        self.assertNotIn(AuthType.OPENID, extracted_types)


if __name__ == "__main__":
    unittest.main()
