# plan1
P2P heterogeneous cluster written in Rust

- Read config

- Initialize internal database connection
    - Verify state of cluster database

- Start http listener
    - implement https

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
