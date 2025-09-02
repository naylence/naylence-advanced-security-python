"""
Abstract base class for certificate management in FAME nodes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from naylence.fame.core import NodeWelcomeFrame
from naylence.fame.node.node_like import NodeLike


class CertificateManager(ABC):
    """
    Abstract base class for certificate management.

    This interface defines the contract for certificate managers that handle
    certificate provisioning, validation, and lifecycle management for FAME nodes.
    """

    def __init__(self, **kwargs):
        """Initialize the certificate manager."""
        pass

    @abstractmethod
    async def on_node_started(self, node: NodeLike) -> None:
        """
        Handle certificate provisioning when a node has started.

        This method is called when a node has completed initialization
        and is ready for operation.

        Args:
            node: The node that has been started
        """
        pass

    @abstractmethod
    async def on_welcome(self, welcome_frame: NodeWelcomeFrame) -> None:
        """
        Handle certificate provisioning after receiving a welcome frame.

        This method is called when a child node receives a welcome frame
        from its parent and needs to provision a certificate.

        Args:
            welcome_frame: NodeWelcomeFrame from admission process
        """
        pass

    async def ensure_root_certificate(
        self,
        node_id: str,
        physical_path: str,
        logicals: Optional[list[str]] = None,
    ) -> bool:
        """
        Ensure the node has a valid certificate for root node operations.

        This is a convenience method for root nodes that need to ensure
        they have a valid certificate before starting operations.

        Args:
            node_id: Node identifier
            physical_path: Physical path for the node
            logicals: List of logical addresses the node will serve

        Returns:
            True if certificate is available or not needed, False otherwise
        """
        # Default implementation delegates to the internal method if available
        if hasattr(self, "_ensure_node_certificate"):
            return await self._ensure_node_certificate(
                node_id=node_id,
                physical_path=physical_path,
                logicals=logicals or [],
            )

        # For managers that don't require certificates, return True
        return True
