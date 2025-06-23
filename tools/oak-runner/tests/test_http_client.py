#!/usr/bin/env python3
"""
Tests for the HTTP Client in OAK Runner

This file contains tests for the HTTPExecutor class in the OAK Runner library,
with a focus on authentication handling.
"""
import pytest
from unittest.mock import Mock
import logging

from oak_runner.auth.credentials.models import Credential
from oak_runner.auth.models import SecurityOption, SecurityRequirement, RequestAuthValue, AuthLocation
from oak_runner.http import HTTPExecutor

logger = logging.getLogger(__name__)

class MockCredentialProvider:
    """Mock credential provider for testing - ONLY mock out what we need"""

    def get_credentials(self, security_options, fetch_options):
        """Mock implementation of get_credentials"""
        return []


@pytest.fixture
def basic_http_client() -> HTTPExecutor:
    return HTTPExecutor()


@pytest.fixture
def http_client() -> HTTPExecutor:
    return HTTPExecutor(auth_provider=MockCredentialProvider())


def test_init(basic_http_client: HTTPExecutor):
    """Test that the HTTP client initializes correctly"""
    assert basic_http_client is not None
    assert basic_http_client.auth_provider is None


def test_apply_auth_no_provider(basic_http_client: HTTPExecutor):
    """Test that auth application is skipped when no auth provider is available"""
    headers = {}
    query_params = {}
    cookies = {}

    # No auth provider set
    basic_http_client._apply_auth_to_request(
        "https://example.com", headers, query_params, cookies
    )

    # Should not modify any of the dictionaries
    assert headers == {}
    assert query_params == {}
    assert cookies == {}


def test_apply_auth_query_parameter(http_client: HTTPExecutor):
    """Test applying auth as query parameters"""
    # Mock out the get_credentials to return a credential
    http_client.auth_provider.get_credentials = Mock(
        return_value=[
            Credential(
                id="test-credential-id",
                request_auth_value=RequestAuthValue(
                    location=AuthLocation.QUERY,
                    name="api-key",
                    auth_value="test-api-key-12345"
                )
            )
        ]
    )

    headers = {}
    query_params = {}
    cookies = {}

    # Create security options
    security_options = [
        SecurityOption(
            requirements=[
                SecurityRequirement(scheme_name="api-key", scopes=[])
            ]
        )
    ]

    # Apply auth
    http_client._apply_auth_to_request(
        "https://example.com", headers, query_params, cookies, security_options
    )

    # Check that query parameters were updated correctly
    assert query_params == {"api-key": "test-api-key-12345"}
    # Headers and cookies should remain empty
    assert headers == {}
    assert cookies == {}


def test_apply_auth_header(http_client: HTTPExecutor):
    """Test applying auth as headers"""
    # Create mock auth provider with header auth
    http_client.auth_provider.get_credentials = Mock(
        return_value=[
            Credential(
                id="test-credential-auth-id",
                request_auth_value=RequestAuthValue(
                    location=AuthLocation.HEADER,
                    name="X-Api-Key",
                    auth_value="test-api-key-12345"
                )
            )
        ]
    )
    headers = {}
    query_params = {}
    cookies = {}

    # Create security options
    security_options = [
        SecurityOption(
            requirements=[
                SecurityRequirement(scheme_name="X-Api-Key", scopes=[])
            ]
        )
    ]

    # Apply auth
    http_client._apply_auth_to_request(
        "https://example.com", headers, query_params, cookies, security_options
    )

    # Check that headers were updated correctly
    assert headers == {"X-Api-Key": "test-api-key-12345"}
    # Query params and cookies should remain empty
    assert query_params == {}
    assert cookies == {}


def test_apply_auth_cookie(http_client: HTTPExecutor):
    """Test applying auth as cookies"""

    http_client.auth_provider.get_credentials = Mock(
        return_value=[
            Credential(
                id="test-credential-auth-id",
                request_auth_value=RequestAuthValue(
                    location=AuthLocation.COOKIE,
                    name="session",
                    auth_value="test-session-id-12345"
                )
            )
        ]
    )
    headers = {}
    query_params = {}
    cookies = {}

    # Create security options
    security_options = [
        SecurityOption(
            requirements=[
                SecurityRequirement(scheme_name="session", scopes=[])
            ]
        )
    ]

    # Apply auth
    http_client._apply_auth_to_request(
        "https://example.com", headers, query_params, cookies, security_options
    )

    # Check that cookies were updated correctly
    assert cookies == {"session": "test-session-id-12345"}
    # Headers and query params should remain empty
    assert headers == {}
    assert query_params == {}


def test_apply_auth_multiple_requirements(http_client: HTTPExecutor):
    """Test applying auth with multiple requirements in different locations"""
    # Create mock auth provider with multiple auth requirements

    http_client.auth_provider.get_credentials = Mock(
        return_value=[
            Credential(
                id="test-credential-auth-id",
                request_auth_value=RequestAuthValue(
                    location=AuthLocation.QUERY,
                    name="api-key",
                    auth_value="test-api-key-12345"
                )
            ),
            Credential(
                id="test-credential-auth-id",
                request_auth_value=RequestAuthValue(
                    location=AuthLocation.HEADER,
                    name="X-Client-Id",
                    auth_value="client-12345"
                )
            ),
            Credential(
                id="test-credential-auth-id",
                request_auth_value=RequestAuthValue(
                    location=AuthLocation.COOKIE,
                    name="session",
                    auth_value="test-session-id-12345"
                )
            )
        ]
    )
    headers = {}
    query_params = {}
    cookies = {}

    # Create security options
    security_options = [
        SecurityOption(
            requirements=[
                SecurityRequirement(scheme_name="api-key", scopes=[]),
                SecurityRequirement(scheme_name="X-Client-Id", scopes=[]),
                SecurityRequirement(scheme_name="session", scopes=[]),
            ]
        )
    ]

    # Apply auth
    http_client._apply_auth_to_request(
        "https://example.com", headers, query_params, cookies, security_options
    )

    # Check that all parameters were updated correctly
    assert query_params == {"api-key": "test-api-key-12345"}
    assert headers == {"X-Client-Id": "client-12345"}
    assert cookies == {"session": "test-session-id-12345"}


def test_apply_auth_missing_value(http_client: HTTPExecutor):
    """Test handling of missing auth values"""
    # Create mock auth provider with auth requirement but missing value
    http_client.auth_provider.get_credentials = Mock(
        return_value=[
            Credential(
                id="test-credential-auth-id",
                request_auth_value=None
            )
        ]
    )

    headers = {}
    query_params = {}
    cookies = {}

    # Create security options
    security_options = [
        SecurityOption(
            requirements=[
                SecurityRequirement(scheme_name="api-key", scopes=[])
            ]
        )
    ]

    # Apply auth
    http_client._apply_auth_to_request(
        "https://example.com", headers, query_params, cookies, security_options
    )

    # All dictionaries should remain empty
    assert headers == {}
    assert query_params == {}
    assert cookies == {}


@pytest.mark.skip("Was broken before, what should happen?")
def test_apply_auth_unknown_location(http_client: HTTPExecutor):
    """Test handling of unknown auth location (should default to header)"""
    # Create mock auth provider with unknown auth location
    http_client.auth_provider.get_credentials = Mock(
        return_value=[
            Credential(
                id="test-credential-auth-id",
                request_auth_value=RequestAuthValue(
                    location="unknown",  # Invalid location - this doesnt pass pydantic validation
                    name="api-key",
                    auth_value="test-api-key-12345"
                )
            )
        ]
    )

    headers = {}
    query_params = {}
    cookies = {}

    # Create security options
    security_options = [
        SecurityOption(
            requirements=[
                SecurityRequirement(scheme_name="api-key", scopes=[])
            ]
        )
    ]

    # Apply auth
    http_client._apply_auth_to_request(
        "https://example.com", headers, query_params, cookies, security_options
    )

    # Should default to header
    assert headers == {"api-key": "test-api-key-12345"}
    assert query_params == {}
    assert cookies == {}


def mock_get_credentials(request, options) -> list[Credential]:
    logger.debug(f"Mock get_credentials called with options: {options}")
    cred1 = Credential(
                id="test-credential-auth-id",
                request_auth_value=RequestAuthValue(
                    location=AuthLocation.QUERY,
                    name="api1-key",
                    auth_value="api1-key-value"
                )
            )
        
    cred2 = Credential(
                id="test-credential-auth-id",
                request_auth_value=RequestAuthValue(
                    location=AuthLocation.HEADER,
                    name="api2-key",
                    auth_value="api2-key-value"
                )
            )
        
    if options.source_name == "api1":
        return [cred1]
    elif options.source_name == "api2":
        return [cred2]
    else:
        return [cred1, cred2]


def test_apply_auth_multiple_apis(http_client: HTTPExecutor):
    """Test applying auth from multiple APIs"""
    # Create mock auth provider with multiple APIs
    http_client.auth_provider.get_credentials = Mock(side_effect=mock_get_credentials)

    headers = {}
    query_params = {}
    cookies = {}

    # Create security options
    security_options = [
        SecurityOption(
            requirements=[
                SecurityRequirement(scheme_name="api1-key", scopes=[]),
                SecurityRequirement(scheme_name="api2-key", scopes=[]),
            ]
        )
    ]

    # Apply auth
    http_client._apply_auth_to_request(
        "https://example.com", headers, query_params, cookies, security_options
    )

    # Both APIs' auth should be applied
    assert query_params == {"api1-key": "api1-key-value"}
    assert headers == {"api2-key": "api2-key-value"}
    assert cookies == {}
