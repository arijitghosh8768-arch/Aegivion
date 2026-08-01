from abc import ABC, abstractmethod
from typing import Dict, List, Any

class CloudProvider(ABC):
    """
    Abstract Base Class for all Cloud Providers (AWS, Azure, GCP).
    Provides connection validation, asset collection, and account information retrieval.
    """

    @abstractmethod
    def validate_connection(self) -> bool:
        """
        Validates connection to the cloud provider.
        Returns:
            bool: True if connection is validated, False otherwise.
        """
        pass

    @abstractmethod
    def collect_assets(self) -> List[Dict[str, Any]]:
        """
        Collects assets from the cloud provider.
        Returns:
            List[Dict[str, Any]]: List of normalized assets.
        """
        pass

    @abstractmethod
    def get_account_info(self) -> Dict[str, Any]:
        """
        Retrieves generic account information from the provider.
        Returns:
            Dict[str, Any]: Dict containing account details like provider name, account ID, and default region.
        """
        pass
