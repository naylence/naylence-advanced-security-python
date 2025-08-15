# Test Certificate Data

This directory contains test certificates and keys for certificate validation testing.

## Generated Test Data

When the full test suite is enabled (cryptography package available), test certificates
will be generated with the following characteristics:

### Root CA
- 20-year validity  
- Ed25519 signature algorithm
- Basic constraints: CA=true, no path length limit
- Key usage: Certificate Sign, CRL Sign

### Intermediate CA  
- 5-year validity
- Ed25519 signature algorithm  
- Basic constraints: CA=true, path length=0
- Key usage: Certificate Sign, CRL Sign
- Name constraints: permitted subtrees for logicals

### Node Certificates
- 1-year validity
- Ed25519 signature algorithm
- Subject Alternative Names with:
  - Physical path URIs: `naylence-phys:///zone/rack/node`
  - Logical URIs: `naylence:///region/service/node`
- Key usage: Digital Signature
- Extended key usage: Client Auth, Server Auth

## Certificate Profile

### Physical Path URIs
Format: `naylence-phys:///<physical-path>`
Example: `naylence-phys:///us-east-1/rack-42/node-123`

### Logical Path URIs  
Format: `naylence:///<logical-path>`
Example: `naylence:///us-east-1/agents/node-123`

### Name Constraints
Intermediate CAs use name constraints to restrict the logicals
they can issue certificates for. For example:

Permitted subtrees: `naylence:///us-east-1/`

This allows the intermediate CA to issue certificates for any logical
path under `us-east-1` but prevents issuing for other regions.
