[![Join our Discord](https://img.shields.io/badge/Discord-Join%20Chat-blue?logo=discord)](https://discord.gg/nwZAeqdv7y)

# Naylence Advanced Security

**Naylence Advanced Security** is a high‑assurance extension for the [Naylence Agentic Fabric](https://github.com/naylence) that delivers advanced cryptographic and policy‑driven protections for multi‑agent systems. It is designed for environments where agents, services, and organizations must interact across trust domains while preserving **confidentiality, integrity, durability, and policy compliance**.

At its core, Naylence already provides a zero‑trust, message‑oriented backbone for federated agents. This package extends that foundation with **sealed overlay encryption**, **SPIFFE/X.509 workload identities**, **secure sticky sessions**, and **secure load balancing** that make the system resilient in complex, federated, and regulated deployments.

---

## Key Features

* **Overlay end‑to‑end encryption (E2EE) & Sealed Channels**
  Adds a cryptographic layer on top of transport (TLS). Messages remain encrypted and authenticated **across multiple hops**, even if intermediate sentinels or networks are compromised.

* **Envelope Signing & Identity Assurance**
  Uses **X.509/SPIFFE‑style identities (SVIDs)** so every envelope is verifiable to its origin—enabling tamper‑resistant audit trails and fine‑grained policy.

* **Secure Sticky Sessions & Load Balancing**
  Cryptographically binds long‑running conversations to the initiating security context, and enables **identity‑aware load balancing** without sacrificing end‑to‑end protections.

* **Durable Cross‑Domain Trust**
  Enables secure federation across orgs or clouds, where \*\*policies—not perimeter assumptions—\*\*determine who can talk to whom.

---

## Security Profiles

The OSS **`naylence-runtime`** package ships the following profiles **out of the box**:

* **`open`** – minimal controls for local/dev.
* **`gated`** – OAuth2/JWT‑gated admission (authn/authz at the edge).
* **`overlay`** – message **signing** for provenance and tamper‑evidence.

This **Advanced Security** package **enables and implements**:

* **`strict-overlay`** – maximum assurance profile combining:

  * **SPIFFE/X.509 workload identities (SVIDs)**
  * **sealed overlay encryption** (true end‑to‑end, multi‑hop confidentiality)
  * **identity‑aware, secure load balancing** and **secure sticky sessions**

> In short: use `open`/`gated`/`overlay` with the OSS runtime; install **Naylence Advanced Security** to access **`strict‑overlay`** and the capabilities above.

---

## Why Advanced Security?

Agent orchestration introduces unique risks:

* Messages often cross **multiple hops** and **administrative domains**.
* Long‑running jobs and sticky sessions can span **hours or days**.
* Agents may be **mobile, ephemeral, or untrusted** in their deployment context.

Advanced Security ensures that **security travels with the message**, not the perimeter—making zero‑trust the default posture.

---

## Use Cases

* **Federated AI Agent Systems** — Secure orchestration across departments or partner orgs.
* **Cross‑Cloud Workflows** — Durable, encrypted communication across cloud providers and trust boundaries.
* **Regulated Environments** — Fine‑grained, auditable controls for healthcare, finance, or defense.
* **Multi‑tenant Platforms** — Strong tenant isolation and policy‑based routing in agent platforms.

---

## Links

* **Advanced Security (this repo):** [https://github.com/naylence/naylence-advanced-security-python](https://github.com/naylence/naylence-advanced-security-python)
* **Runtime (OSS profiles & fabric):** [https://github.com/naylence/naylence-runtime-python](https://github.com/naylence/naylence-runtime-python)
* **Agent SDK (build agents/clients):** [https://github.com/naylence/naylence-agent-sdk-python](https://github.com/naylence/naylence-agent-sdk-python)
* **Examples (runnable demos):** [https://github.com/naylence/naylence-examples-python](https://github.com/naylence/naylence-examples-python)

---

## License

This package is distributed under the **Business Source License (BSL)**. See [`LICENSE`](./LICENSE) for full terms.
