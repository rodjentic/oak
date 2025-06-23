"""
Credential Provider System - A flexible, extensible credential management system
with composite parts, fetch strategies, caching, and validation pipelines.
"""

import logging
from typing import Dict, List
import requests

from oak_runner.auth.auth_parser import AuthRequirement
from oak_runner.auth.credentials.models import Credential
from oak_runner.auth.credentials.cache import InMemoryCredentialCache, CredentialCache
from oak_runner.auth.credentials.fetch import FetchStrategy, EnvironmentVariableFetchStrategy, FetchOptions
from oak_runner.auth.credentials.transform import CredentialTransformer, CredentialToRequestAuthValueTransformer
from oak_runner.auth.credentials.validate import CredentialValidator, ValidCredentialValidator
from oak_runner.auth.models import SecurityOption, RequestAuthValue
from oak_runner.utils import deprecated, run_async

logger = logging.getLogger(__name__)

# Main credential provider class
class CredentialProvider:
    """
    Main credential provider that orchestrates fetching, caching, 
    validation, and transformation.
    """
    
    def __init__(
        self,
        strategy: FetchStrategy,
        cache: CredentialCache | None = None,
        validators: List[CredentialValidator] | None = None,
        transformers: List[CredentialTransformer] | None = None
    ):
        self.strategy: FetchStrategy = strategy
        self.cache: CredentialCache = cache or InMemoryCredentialCache()
        self.validators: List[CredentialValidator] = validators or []
        self.transformers: List[CredentialTransformer] = transformers or []

        self._is_populated: bool = False
    
    ## Public API ##
    async def populate(self, auth_requirements: List[AuthRequirement]):
        """
        Populates the provider with the given auth requirements.
        This is a one-time operation that is run when the provider is initialized, however it is idempotent.
        """
        if not self._is_populated:
            await self.strategy.populate(auth_requirements)
            self._is_populated = True
    
    async def get_credential(self, request: SecurityOption, fetch_options: FetchOptions | None = None) -> List[Credential]:
        if not self._is_populated:
            raise Exception("Provider has not been populated, run populate() first.")
        
        # Fetch credential
        logger.debug(f"Fetching credential for {request=}")
        credentials = await self.strategy.fetch([request], fetch_options)
        
        # Validate
        if not await self._are_valid_credentials(credentials):
            logger.warning(f"Failed to fetch valid credentials for {request=}")
            return []  # TODO old behaviour, probably change it

        # Transform
        credentials = await self._transform_credentials(credentials)
        return credentials
    
    async def get_credentials(self, requests: List[SecurityOption], fetch_options: FetchOptions | None = None) -> List[Credential]:
        credentials = []
        for request in requests:
            credentials.extend(await self.get_credential(request, fetch_options))
        return credentials

    # Deprecated API #
    @deprecated("Use get_credentials() instead, this will be removed in a future release")
    def resolve_credentials(self, security_options: list[SecurityOption], source_name: str | None = None) -> list[RequestAuthValue]:
        creds = run_async(self.get_credentials(security_options, FetchOptions(source_name=source_name)))
        return [cred.request_auth_value for cred in creds]

    ## Private API ##
    async def _are_valid_credentials(self, credentials: List[Credential]) -> bool:
        """Run all validators on the credentials."""
        for credential in credentials:
            for validator in self.validators:
                if not await validator.validate(credential):
                    return False
        return True
    
    async def _transform_credentials(self, credentials: List[Credential]) -> List[Credential]:
        """Apply all transformers to the credentials."""
        results = []
        for credential in credentials:
            result = credential
            for transformer in self.transformers:
                result = await transformer.transform(result)
            results.append(result)
        return results
    

# Factory for common configurations
class CredentialProviderFactory:
    """Factory for creating common credential provider configurations."""
    
    @staticmethod
    def create_default(env_mapping: Dict[str, str], http_client: requests.Session | None = None) -> CredentialProvider:
        """Create a default credential provider with EnvironmentVariableFetchStrategy"""
        return CredentialProvider(
            strategy=EnvironmentVariableFetchStrategy(env_mapping, http_client),
            validators=[ValidCredentialValidator()],
            transformers=[CredentialToRequestAuthValueTransformer()]
        )
