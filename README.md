# Petnicki blockchain node

Run one node with the protocol difficulty:

```bash
go run . -addr :8080
```

The node persists validated blocks, its pending transaction list, and its miner
private key in `node-state.json`. If the file has no private key (including
state files created by older versions), one is generated on startup and saved.
Keep this file private: it preserves the node's identity. The node mines locally
and prints each successfully mined block. Use `Ctrl+C` to stop it.

For fast local experiments, lower the difficulty and disable network lag:

```bash
go run . -addr :8080 -difficulty 12 -no-lag
```

Start a second peer (use a separate data file) with:

```bash
go run . -addr :8081 -peers http://localhost:8080 -data node-8081.json
```

Supported protocol endpoints are `GET /tip`, `GET /blocks/{hash}`,
`POST /transactions`, and `POST /blocks`. Incoming JSON is validated strictly:
only the specified fields, lowercase hexadecimal, canonical JSON integers,
Ed25519 signatures, ownership, nonce order, parent linkage, and proof of work
are accepted.

Useful flags:

- `-difficulty 20` sets the required number of leading zero bits.
- `-peers URL,URL` configures HTTP peers.
- `-no-mine` runs a syncing/validating node without mining.
- `-no-lag` disables simulated network lag. With lag enabled, every peer
  request and response independently waits 100–500 ms and has a 5% chance of
  being lost. A successful HTTP round trip therefore has 200–1000 ms of added
  delay (600 ms on average).
- `-data FILE` changes the local persistence file; `-data ''` disables it.
