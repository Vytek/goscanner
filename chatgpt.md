I’ll inspect the current TCP packet construction and reply matching first, then add sequence/acknowledgment handling at the smallest owning abstraction and validate it with Go tests.

Searched for regex `Seq|Ack|synScanPort|layers.TCP` (`**/main.go`), 40 results

Read [](goscanner/main.go#1-1), lines 1 to 190

Read [](goscanner/main.go#250-250), lines 250 to 301

The current SYN uses a timestamp-derived sequence and accepts any SYN-ACK to the ephemeral port, so it can misassociate stale traffic. I’ll introduce a concurrency-safe TCP sequence generator and require replies to acknowledge exactly `sequence + 1`; a small unit test can disconfirm both wraparound and reply-validation behavior without sending packets.

Read [](goscanner/main.go#160-160), lines 160 to 290

I’m editing the packet path now: sequence allocation becomes an explicit atomic component, and SYN-ACK/RST classification will only accept ACK numbers tied to the sent SYN. This preserves the current scan API while fixing correlation under concurrency.

Generating patch (71 lines) in [](goscanner/main.go)


```

```
The sequence correlation is in place. I’m running the focused package check now; it will also expose whether the intervening user edits left any compile-time conflicts.

Ran terminal command: go test ./...

The package compiles. I’ll add narrow deterministic tests for monotonic allocation, wraparound, and rejection of mismatched ACKs, then rerun them; afterward I’ll address one directly blocking runtime issue visible in the current scanner lifecycle.

Generating patch (75 lines) in [](goscanner/main_test.go)


```

```
The tests now pin the sequencer contract and packet matching rules. I’m running them with the race detector because this component exists specifically for concurrent scans.

Ran terminal command: go test -race ./...
Completed with input: go test -race ./...

Race detection is unavailable because this Windows Go environment has CGO disabled, so that check cannot run here. I’ll run the deterministic tests normally, then restore handle initialization in `newScanner`; without it, the current `getHwAddr` and `close` paths dereference a nil pcap handle before any sequenced scan can execute.

Ran terminal command: go test ./...

The sequencer tests pass. I’m making the lifecycle repair now by opening the route interface handle before returning the scanner, matching what `getHwAddr`, `send`, and `close` already require.

Generating patch (15 lines) in [](goscanner/main.go)


```

```
The scanner can now reach the packet path without a nil handle. I’m doing the final package test and static analysis pass.

Ran terminal command: go test ./...

Ran terminal command: go vet ./...

Checked [](goscanner/main.go), [](goscanner/main_test.go), no problems found

Implemented a concurrency-safe TCP sequencer in main.go:

- Atomic 32-bit sequence generation with wraparound.
- Validates SYN-ACK/RST acknowledgments against `sequence + 1`.
- Rejects stale or unrelated replies.
- Restored required pcap handle initialization.
- Added focused tests in main_test.go.

Validation passed: `go test DeepScan.` and `go vet DeepScan.`.

Race testing was unavailable because CGO is disabled.

Made changes.