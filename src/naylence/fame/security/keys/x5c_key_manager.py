import asyncio
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any, Iterable, Optional

from naylence.fame.core import (
    DeliveryOriginType,
    EnvelopeFactory,
    KeyAnnounceFrame,
    local_delivery_context,
)
from naylence.fame.security.cert.util import validate_jwk_x5c_certificate
from naylence.fame.security.keys.key_manager import KeyManager
from naylence.fame.security.keys.key_store import KeyStore
from naylence.fame.util.envelope_context import current_trace_id
from naylence.fame.util.logging import getLogger
from naylence.fame.util.task_spawner import TaskSpawner
from naylence.fame.util.util import secure_digest

if TYPE_CHECKING:
    from naylence.fame.node.node_like import NodeLike
    from naylence.fame.node.routing_node_like import RoutingNodeLike

logger = getLogger(__name__)


class X5CKeyManager(KeyManager, TaskSpawner):
    """Default implementation of KeyManager with certificate expiry management."""

    def __init__(
        self,
        *,
        key_store: KeyStore,
        cert_purge_interval: float = 3600.0,  # Check every hour by default
    ) -> None:
        KeyManager.__init__(self)
        TaskSpawner.__init__(self)
        self._key_store: KeyStore = key_store
        self._cert_purge_interval = cert_purge_interval

        # Context - populated by on_node_started
        self._node: Optional[NodeLike] = None
        self._routing_node: Optional[RoutingNodeLike] = None
        self._purge_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        logger.debug("x5c_key_manager_initialized")

    async def on_node_started(self, node: "NodeLike") -> None:
        """Called when a node has been started and is ready for operation.

        This replaces the deprecated update_context() method and also starts
        the background certificate purging task.
        """
        self._node = node

        # Check if this is a routing node for additional capabilities
        try:
            from naylence.fame.node.routing_node_like import RoutingNodeLike

            if isinstance(node, RoutingNodeLike):
                self._routing_node = node
        except ImportError:
            # RoutingNodeLike not available, skip routing-specific features
            pass

        logger.debug(
            "x5c_key_manager_started",
            node_id=self._node_id,
            physical_path=self._physical_path,
            has_upstream=self._has_upstream,
            cert_purge_interval=self._cert_purge_interval,
        )

        # Start background certificate purging task
        self._shutdown_event.clear()
        self._purge_task = self.spawn(self._certificate_purge_loop(), name=f"cert-purge-{self._node_id}")

    async def on_node_stopped(self, node: "NodeLike") -> None:
        """Called when a node is being stopped and should clean up resources."""
        logger.debug("x5c_key_manager_stopping", node_id=self._node_id)

        # Signal shutdown and wait for purge task to complete
        self._shutdown_event.set()

        if self._purge_task and not self._purge_task.done():
            try:
                await asyncio.wait_for(self._purge_task, timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("key_manager_purge_task_timeout", node_id=self._node_id)
                self._purge_task.cancel()

        # Shutdown all spawned tasks
        await self.shutdown_tasks()

        logger.debug("x5c_key_manager_stopped", node_id=self._node_id)

    @property
    def _has_upstream(self) -> bool:
        return self._node.has_parent if self._node else False

    @property
    def _physical_path(self) -> str:
        """Get the node's physical path."""
        return str(getattr(self._node, "physical_path", "/")) if self._node else "/"

    @property
    def _node_id(self) -> str:
        """Get the node's ID."""
        return str(getattr(self._node, "_id", "")) if self._node else ""

    @property
    def _node_sid(self) -> str:
        """Get the node's secure ID."""
        return str(getattr(self._node, "_sid", "")) if self._node else ""

    @property
    def _envelope_factory(self) -> Optional[EnvelopeFactory]:
        """Get the node's envelope factory."""
        return getattr(self._node, "_envelope_factory", None) if self._node else None

    async def get_key(self, kid: str) -> dict[str, Any]:
        return await self._key_store.get_key(kid)

    async def has_key(self, kid: str) -> bool:
        return await self._key_store.has_key(kid)

    async def add_keys(
        self,
        *,
        keys: list[dict],
        sid: Optional[str] = None,
        physical_path: str,
        system_id: str,
        origin: DeliveryOriginType,
        skip_sid_validation: bool = False,  # New parameter for correlation routing
    ):
        # from naylence.fame.security.cert.util import validate_jwk_x5c_certificate
        from naylence.fame.security.crypto.jwk_validation import (
            JWKValidationError,
            validate_jwk_complete,
        )

        # Pre-validate all keys before processing
        valid_keys = []
        rejected_count = 0  # Get trust store configuration if available
        trust_store_pem = None
        try:
            # Try to get trust store from environment or default configuration
            import os

            trust_store_pem = os.environ.get("FAME_TRUST_STORE_PATH")
            if not trust_store_pem:
                # Check for CA cert file which can serve as trust store
                ca_cert_file = os.environ.get("FAME_CA_CERT_FILE")
                if ca_cert_file:
                    trust_store_pem = ca_cert_file
        except Exception:
            # If we can't get trust store config, proceed without trust store validation
            pass

        for key in keys:
            try:
                # First, basic JWK validation
                validate_jwk_complete(key)

                # For node attach flows, perform strict certificate validation
                if "x5c" in key and trust_store_pem:
                    is_valid, error_msg = validate_jwk_x5c_certificate(
                        key,
                        trust_store_pem=trust_store_pem,
                        enforce_name_constraints=True,
                        strict=False,  # Don't raise exception, just log and reject
                    )

                    if not is_valid:
                        logger.warning(
                            "rejected_key_due_to_certificate_validation_failure",
                            kid=key.get("kid", "unknown"),
                            from_system_id=system_id,
                            from_physical_path=physical_path,
                            origin=origin,
                            error=error_msg,
                            scenario="node_attach",
                        )
                        rejected_count += 1

                        # For node attach, reject the key if certificate validation fails
                        if origin in [DeliveryOriginType.DOWNSTREAM, DeliveryOriginType.UPSTREAM]:
                            continue  # Skip this key

                valid_keys.append(key)

            except JWKValidationError as e:
                logger.warning(
                    "rejected_invalid_jwk_in_announce",
                    kid=key.get("kid", "unknown"),
                    from_system_id=system_id,
                    from_physical_path=physical_path,
                    error=str(e),
                )
                rejected_count += 1
        if not valid_keys:
            logger.warning(
                "no_valid_keys_in_announce",
                from_system_id=system_id,
                from_physical_path=physical_path,
                total_keys=len(keys),
                rejected_count=rejected_count,
            )
            logger.debug(
                "no_valid_keys_after_validation",
                announced_kids=[key.get("kid") for key in keys],
                announced_uses=[key.get("use") for key in keys],
                physical_path=physical_path,
                origin=origin,
                sid=sid,
            )
            return

        logger.debug(
            "validated_keys_for_announce",
            validated_kids=[key.get("kid") for key in valid_keys],
            validated_uses=[key.get("use") for key in valid_keys],
            physical_path=physical_path,
            origin=origin,
            sid=sid,
        )

        logger.debug(
            "adding_keys",
            key_ids=[key["kid"] for key in valid_keys],
            source_system_id=system_id,
            from_physical_path=physical_path,
            trace_id=current_trace_id(),
            origin=origin,
            valid_count=len(valid_keys),
            rejected_count=rejected_count,
        )

        if origin == DeliveryOriginType.LOCAL:
            await self._key_store.add_keys(valid_keys, physical_path=physical_path)
            return

        # if origin not in [
        #     DeliveryOriginType.DOWNSTREAM,
        #     DeliveryOriginType.UPSTREAM,
        #     DeliveryOriginType.PEER,
        # ]:
        #     raise ValueError(f"Cannot add keys from origin type {origin}")

        self_physical_path = self._physical_path

        # Accept key announcements signed by direct links only
        # Skip SID validation for correlation-routed KeyAnnounce messages
        if sid and not skip_sid_validation:
            key_path = None

            if origin == DeliveryOriginType.DOWNSTREAM:
                key_path = str(PurePosixPath(self_physical_path) / system_id)
            elif origin == DeliveryOriginType.UPSTREAM:
                key_path = str(PurePosixPath(self_physical_path).parent)
            elif origin == DeliveryOriginType.PEER:
                key_path = f"/{system_id}"

            assert key_path

            expected_sid = secure_digest(key_path)
            if sid != expected_sid:
                # TODO: security: disconnect the downstream that sent the announcement?
                raise ValueError(f"Invalid downstream sid: {sid}")

        # For downstream origins, ensure the physical path is downstream
        if origin == DeliveryOriginType.DOWNSTREAM:
            normalized_frame_path = physical_path.rstrip("/")
            expected_path_prefix = str(PurePosixPath(self_physical_path) / system_id / "")
            if not (normalized_frame_path + "/").startswith(expected_path_prefix):
                raise ValueError(
                    f"Frame physical path {normalized_frame_path} "
                    f"does not match expected prefix {expected_path_prefix}"
                )

        # Remove old encryption keys before adding new ones to handle key rotation
        # This ensures clients/agents can reconnect with fresh encryption keys
        # Keys may be stored under multiple paths (physical path AND logical addresses)
        # so we need to remove them from ALL paths, not just the physical path
        has_encryption_keys = any(key.get("use") == "enc" for key in valid_keys)
        if has_encryption_keys:
            logger.debug(
                "checking_for_old_encryption_keys_to_remove",
                physical_path=physical_path,
                origin=origin,
                new_enc_keys=[k["kid"] for k in valid_keys if k.get("use") == "enc"],
            )
            try:
                # Get all encryption keys across ALL paths to find stale keys
                # This is necessary because keys can be stored under multiple paths:
                # 1. Physical path: /system_id/node_id
                # 2. Logical addresses: participant@/system_id/node_id (e.g., __rpc__@/...)
                all_keys_by_path = await self._key_store.get_keys_grouped_by_path()

                # Find all encryption keys that match our physical path or related logical addresses
                # Related logical addresses are those that end with the physical path
                old_enc_keys_to_check = []
                paths_with_old_keys = []

                for path, keys_at_path in all_keys_by_path.items():
                    # Match if path equals physical_path OR ends with physical_path (logical address case)
                    if path == physical_path or path.endswith(f"@{physical_path}"):
                        enc_keys_at_path = [k for k in keys_at_path if k.get("use") == "enc"]
                        if enc_keys_at_path:
                            old_enc_keys_to_check.extend(enc_keys_at_path)
                            paths_with_old_keys.append(path)

                logger.debug(
                    "found_existing_encryption_keys_across_paths",
                    physical_path=physical_path,
                    paths_checked=paths_with_old_keys,
                    existing_enc_key_ids=[k["kid"] for k in old_enc_keys_to_check],
                )

                if old_enc_keys_to_check:
                    # Get the new encryption key IDs being added
                    new_enc_key_ids = {k["kid"] for k in valid_keys if k.get("use") == "enc"}
                    # Only remove old encryption keys that are not in the new set
                    # Use a set to deduplicate in case same key appears under multiple paths
                    keys_to_remove = list(
                        {k["kid"] for k in old_enc_keys_to_check if k["kid"] not in new_enc_key_ids}
                    )

                    if keys_to_remove:
                        logger.info(
                            "removing_old_encryption_keys_for_key_rotation",
                            physical_path=physical_path,
                            paths_with_old_keys=paths_with_old_keys,
                            old_key_ids=keys_to_remove,
                            new_key_ids=list(new_enc_key_ids),
                            origin=origin,
                        )
                        for kid in keys_to_remove:
                            # remove_key() removes the key from ALL paths where it's stored
                            await self._key_store.remove_key(kid)
                            logger.debug("removed_old_encryption_key_from_all_paths", kid=kid)
            except Exception as e:
                logger.warning(
                    "failed_to_remove_old_encryption_keys",
                    physical_path=physical_path,
                    error=str(e),
                    origin=origin,
                )
                # Continue with adding new keys even if removal fails

        await self._key_store.add_keys(valid_keys, physical_path=physical_path)

        if origin == DeliveryOriginType.DOWNSTREAM:
            await self._announce_path_keys(valid_keys, physical_path, origin)
        else:
            logger.debug(
                "skip_announcing_keys_to_upstream",
                key_ids=[key["kid"] for key in keys if "kid" in key],
                from_physical_path=physical_path,
                has_upsteam=self._has_upstream,
            )

    async def _announce_path_keys(
        self,
        keys: list[dict[str, Any]],
        from_physical_path: str,
        origin: DeliveryOriginType,
    ):
        # Only announce if we have somewhere to announce to
        if not (
            self._has_upstream or (self._routing_node and hasattr(self._routing_node, "forward_to_peers"))
        ):
            logger.debug(
                "skip_announcing_keys_no_destination",
                key_ids=[key["kid"] for key in keys if "kid" in key],
                from_physical_path=from_physical_path,
                has_upstream=self._has_upstream,
                has_routing_node=self._routing_node is not None,
            )
            return

        logger.debug(
            "announcing_keys_to_upstream",
            key_ids=[key["kid"] for key in keys if "kid" in key],
            from_physical_path=from_physical_path,
        )

        envelope_factory = self._envelope_factory
        if not envelope_factory:
            raise RuntimeError("Envelope factory not available - key manager not properly initialized")

        env = envelope_factory.create_envelope(
            frame=KeyAnnounceFrame(keys=keys, physical_path=from_physical_path)
        )

        if self._has_upstream:
            node_id = self._node_id
            if not node_id:
                raise RuntimeError("Node ID not available - key manager not properly initialized")
            if not self._node:
                raise RuntimeError("Node not available - key manager not properly initialized")
            await self._node.forward_upstream(env, local_delivery_context(node_id))

        if self._routing_node and hasattr(self._routing_node, "forward_to_peers"):
            node_id = self._node_id
            if not node_id:
                raise RuntimeError("Node ID not available - key manager not properly initialized")
            await self._routing_node.forward_to_peers(env, None, None, local_delivery_context(node_id))

    async def announce_keys_to_upstream(self):
        if not self._has_upstream:
            return

        self_physical_path = self._physical_path

        logger.debug("reannouncing_keys_upstream")

        sem = asyncio.Semaphore(16)  # throttle burst to 16 in-flight

        async def _announce(path: str, keys_per_sid: list[dict[str, Any]]) -> None:
            if not path.startswith(self_physical_path):
                return
            async with sem:
                try:
                    await self._announce_path_keys(keys_per_sid, path, DeliveryOriginType.DOWNSTREAM)
                except Exception as e:
                    logger.error("announce_key_failed", error=e, exc_info=True)

        # TODO: get keys relevant to the origin
        await asyncio.gather(
            *(
                _announce(path, keys)
                for path, keys in (await self._key_store.get_keys_grouped_by_path()).items()
            )
        )

        logger.debug("reannounce_keys_upstream_completed")

    def _get_keys_to_announce_upstream(self) -> list[list[dict[str, Any]]]: ...

    def _should_announce_upsteam(self, key: dict[str, Any]) -> bool:
        return False

    async def handle_key_request(
        self,
        kid: str,
        from_seg: str,
        *,
        physical_path: str | None,
        origin: DeliveryOriginType,
        corr_id: Optional[str] = None,
        original_client_sid: Optional[str] = None,
    ) -> None:
        """
        Answer a KeyRequest with a signed KeyAnnounce.

        Parameters
        ----------
        kid : str
            The requested key-id.
        from_seg : str
            The segment we received the request *from* (so we can target the reply
            if it came from downstream).
        physical_path : str | None
            Optional path filter for bulk requests.
        origin : DeliveryOriginType
            UPSTREAM if the request travelled down from our parent,
            DOWNSTREAM if it came up from a child.
        corr_id : str | None
            Optional correlation ID for the request.
        original_client_sid : str | None
            Original client session ID for sticky routing.
        """

        logger.trace("handling_key_request", kid=kid, corr_id=corr_id)

        jwk = None
        # 1) Gather the key(s)
        try:
            jwk = await self._key_store.get_key(kid)
            keys = [jwk]
        except ValueError:
            if physical_path is None:
                logger.trace(
                    "handling_key_request_failed",
                    kid=kid,
                    corr_id=corr_id,
                    reason="key_not_found",
                )
                raise  # we really have nothing suitable
            keys = list(await self._key_store.get_keys_for_path(physical_path))

        assert jwk

        # 2) Build & sign the KeyAnnounce
        envelope_factory = self._envelope_factory
        if not envelope_factory:
            raise RuntimeError("Envelope factory not available - key manager not properly initialized")

        env = envelope_factory.create_envelope(
            frame=KeyAnnounceFrame(
                keys=keys,
                physical_path=jwk["physical_path"],
            ),
            corr_id=corr_id,
        )

        # 3) Send it the right way with proper delivery context
        node_id = self._node_id
        if not node_id:
            raise RuntimeError("Node ID not available - key manager not properly initialized")

        delivery_context = local_delivery_context(node_id)

        # Request stickiness for encryption keys
        if jwk.get("use") == "enc":
            delivery_context.stickiness_required = True
            delivery_context.sticky_sid = original_client_sid  # Set original client SID for AFT
            logger.debug(
                "key_announce_stickiness_set",
                kid=kid,
                corr_id=corr_id,
                key_use=jwk.get("use"),
                original_client_sid=original_client_sid,
            )

        if origin is DeliveryOriginType.DOWNSTREAM:
            if not self._routing_node:
                raise RuntimeError(
                    "Forward downstream not available - routing functionality not initialized"
                )
            # The child that asked lives on `from_seg`
            await self._routing_node.forward_to_route(from_seg, env, delivery_context)
        else:  # origin == UPSTREAM
            if not self._node:
                raise RuntimeError("Node not available - key manager not properly initialized")
            await self._node.forward_upstream(env, delivery_context)

    async def remove_keys_for_path(self, physical_path: str) -> int:
        """Remove all keys associated with the given physical path.

        This is useful when a system reconnects with new keys - we want to
        remove all old keys for that system before adding the new ones.

        Returns the number of keys removed.
        """
        removed_count = await self._key_store.remove_keys_for_path(physical_path)
        logger.debug(
            "removed_keys_for_path",
            physical_path=physical_path,
            removed_count=removed_count,
        )
        return removed_count

    async def get_keys_for_path(self, physical_path: str) -> Iterable[dict[str, Any]]:
        """Get all keys associated with the given physical path."""
        return await self._key_store.get_keys_for_path(physical_path)

    async def purge_expired_certificates(self) -> int:
        """Remove expired certificates from storage.

        This method checks all stored keys with x5c certificate chains
        and removes those that have expired.

        Returns:
            The number of certificates that were purged.
        """
        logger.debug("certificate_purge_starting")

        try:
            # Import cryptography modules for certificate parsing
            import base64
            import datetime

            from cryptography import x509
        except ImportError:
            logger.warning("certificate_purge_skipped", reason="cryptography_not_available")
            return 0

        purged_count = 0
        now = datetime.datetime.now(datetime.timezone.utc)

        # Get all keys from the key store
        all_keys = []
        for path_keys in (await self._key_store.get_keys_grouped_by_path()).values():
            all_keys.extend(path_keys)

        keys_to_remove = []

        for key in all_keys:
            kid = key.get("kid", "unknown")

            # Only check keys with certificate chains
            if "x5c" not in key or not key["x5c"]:
                continue

            try:
                # Parse the leaf certificate from x5c
                x5c = key["x5c"]
                if not isinstance(x5c, list) or len(x5c) == 0:
                    continue

                # Decode the first (leaf) certificate
                cert_der = base64.b64decode(x5c[0])
                cert = x509.load_der_x509_certificate(cert_der)

                # Check if certificate has expired
                if now > cert.not_valid_after_utc:
                    logger.debug(
                        "expired_certificate_found",
                        kid=kid,
                        physical_path=key.get("physical_path", "unknown"),
                        expired_at=cert.not_valid_after_utc.isoformat(),
                        days_expired=(now - cert.not_valid_after_utc).days,
                    )
                    keys_to_remove.append(key)

            except Exception as e:
                logger.warning(
                    "certificate_parsing_failed_during_purge",
                    kid=kid,
                    error=str(e),
                    message="Could not parse certificate for expiry check",
                )
                continue

        # Remove expired certificates
        for key in keys_to_remove:
            try:
                kid = key.get("kid")
                if kid and await self._key_store.has_key(kid):
                    # Remove the key from the store
                    await self._key_store.remove_key(kid)
                    purged_count += 1
                    logger.debug(
                        "expired_certificate_purged",
                        kid=kid,
                        physical_path=key.get("physical_path", "unknown"),
                    )
            except Exception as e:
                logger.error(
                    "certificate_purge_failed",
                    kid=key.get("kid", "unknown"),
                    error=str(e),
                    exc_info=True,
                )

        if purged_count > 0:
            logger.debug(
                "certificate_purge_completed",
                purged_count=purged_count,
                total_checked=len([k for k in all_keys if "x5c" in k]),
            )
        else:
            logger.debug("certificate_purge_completed", purged_count=0)

        return purged_count

    async def _certificate_purge_loop(self) -> None:
        """Background task that periodically purges expired certificates."""
        logger.debug(
            "certificate_purge_loop_started",
            interval_seconds=self._cert_purge_interval,
            node_id=self._node_id,
        )

        try:
            while not self._shutdown_event.is_set():
                try:
                    # Wait for the interval or shutdown signal
                    await asyncio.wait_for(self._shutdown_event.wait(), timeout=self._cert_purge_interval)
                    # If we get here, shutdown was signaled
                    break
                except asyncio.TimeoutError:
                    # Timeout is normal - time to do another purge cycle
                    pass

                # Perform certificate purging
                try:
                    purged = await self.purge_expired_certificates()
                    if purged > 0:
                        logger.debug(
                            "certificate_purge_cycle_completed",
                            purged_count=purged,
                            node_id=self._node_id,
                        )
                except Exception as e:
                    logger.error(
                        "certificate_purge_cycle_failed",
                        node_id=self._node_id,
                        error=str(e),
                        exc_info=True,
                    )

        except asyncio.CancelledError:
            logger.debug("certificate_purge_loop_cancelled", node_id=self._node_id)
            raise
        except Exception as e:
            logger.error(
                "certificate_purge_loop_failed",
                node_id=self._node_id,
                error=str(e),
                exc_info=True,
            )
        finally:
            logger.debug("certificate_purge_loop_stopped", node_id=self._node_id)
