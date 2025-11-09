# plan1
P2P heterogeneous cluster written in Rust

## Status: HTTPS with Bidirectional TOFU ✅

The HTTPS listener is now fully implemented with:
- ✅ Automatic certificate generation
- ✅ Trust-On-First-Use (TOFU) certificate handling
- ✅ Bidirectional trust negotiation between peers
- ✅ Certificate pinning and verification
- ✅ **HTTP-to-HTTPS automatic redirect** (NEW!)

**See [QUICKSTART.md](QUICKSTART.md) for usage** or [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) for details.

⚠️ **Seeing certificate errors?** See [CERT_EXCHANGE_TROUBLESHOOTING.md](CERT_EXCHANGE_TROUBLESHOOTING.md) - browser errors are expected!

💡 **Running peers on different ports?** See [PEER_PORT_HEADER.md](PEER_PORT_HEADER.md) for `X-Peer-Port` header usage.

---

## Project Roadmap

- Read config

- Initialize internal database connection
    - Verify state of cluster database

- Start http listener
    - ✅ implement https (COMPLETED - see docs above)

- Time keeping
    - scheduling
    - synchronization

- Message types
    - join
    - status
    - time
    - 

- Database objections
    - connections
        - peers
        - external
    - peers
    - tasks/actions
    - requests
    - errors
        - internal
        - external
    - statuses
        - self
        - peers
        - cluster
        - external
    - telemetry
        - location
        - time
        - date
