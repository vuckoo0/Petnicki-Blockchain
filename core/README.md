# Core node package

`core.go` contains the blockchain node implementation behind the root
executable.

It contains:

- protocol data types and canonical Ed25519/SHA-256 encoding rules;
- strict transaction and block JSON validation;
- chain state, mining, rewards, fork selection, and the mempool;
- the four HTTP endpoint handlers;
- peer broadcast, synchronization, simulated network delay/loss; and
- local block and mempool persistence.

The root `main.go` imports this package and calls `core.Run()`.
