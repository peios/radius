---
title: Authentication Diagnostics
description: Protected attempt timelines, exact authority links, dropped-request reports, and incomplete evidence.
---

`radius diagnostics` and the GXWI Diagnostics section show recorded progress
through authentication. Both read eventd using the caller's identity. radiusd
does not expose a privileged alternative history or store another diagnostic
database. Authentication does not wait for eventd storage or diagnostic
readers.

## Attempts and outcomes

One attempt represents one authentication conversation. Retransmissions retain
its identifier. A fresh conversation, including reauthentication, gets
another.
The identifier is displayed as 32 hexadecimal digits. It is not a credential.

Milestones cover method selection, TLS, credential verification, network
permissions, assignment, and accounting admission. Repeated polling does not
create another milestone for the same result under the same configuration.
The final `radiusd.exchange.attempted` event also carries a summary that can
be read independently.

An Accept means the local UDP socket accepted the reply for transmission.
It does not confirm AP admission, DHCP, or internet access. A send failure,
timeout, and credential refusal are separate outcomes. A TLS timeout does not
prove that the person rejected a certificate.

Stage sequence numbers order one attempt. Elapsed milliseconds use the local
monotonic clock. Event timestamps can move after a wall-clock adjustment.
Separate services have separate event orders; nearby timestamps do not prove
that their events belong to the same attempt.

## Finding evidence

Use a bounded time window and inspect whether the result was limited:

```sh
radius diagnostics list --since 900 --username alice
radius diagnostics follow --since 300 --station aa:bb:cc:dd:ee:ff
radius diagnostics show ATTEMPT-ID --since 86400
radius diagnostics drops --since 300
radius diagnostics status
```

`--network` selects an access-policy GUID. `--client` selects a client
configuration GUID. `--username` matches the supplied inner username exactly;
it does not establish identity. Station identifiers are normalized reported
MAC addresses. The outer EAP identity is not recorded.

Personal and configuration filters operate on reconstructed, readable attempts
in the returned record window. This keeps anonymous TLS stages alongside a
later supplied username. A limited record window can omit other matches.
Use a narrower time window or adjust the configured bounds when necessary.

Finite `--json` commands return structured results. The command
`diagnostics follow --json` writes one JSON object per line: `kind=status` for
reader state, or `kind=event` with an authorized record. Stop following with
Ctrl+C.

In GXWI, select Diagnostics, enter filters, and select Follow Live or Refresh
History. Details retain the selected attempt during live updates. A selected
attempt outside the returned readable window remains selected but unavailable.

## Authority and configuration links

An authority supporting the optional PGSS operation GUID supplies an exact
link to `authd.authentication.attempted`. `show` and Read Linked Events query
that GUID and the RADIUS service caller SID. eventd independently authorizes
the authority records. Empty results do not establish that no authority event
exists. An older authority can authenticate without supplying the identifier.

Correlation is not attestation or authorization. Event type names alone do
not prove an emitter's identity. Retain readable kernel event headers when
reviewing evidence. Principal-source events are not joined by guessing from
names or timestamps.

An attempt records the effective authentication fingerprint, relevant
configuration identifiers and observed decisions. Labels and diagnostic
controls do not alter that authentication fingerprint. The saved configuration
fingerprint is separate. Historical decisions are not recomputed against
edited policy. The hypothetical Explain Policy operation remains separate.

Recorded labels remain historical. Open Current Object opens today's readable
configuration, which can differ or be unavailable after deletion or a
permission change. Current configuration never fills a field missing from the
timeline.

## Permissions and privacy

eventd's record and field security descriptors govern both history and live
streams. RADIUS management rights do not automatically grant diagnostic read
rights. The reader does not elevate or query as radiusd. Configuration-read
permission is not required to use independently delegated event access.

Live readers run in the caller's own process. An impersonating host can use
finite history queries on its calling thread, but cannot start a live worker
that would inherit a different process identity. Reader startup checks this
boundary without requiring token-duplication or impersonation rights.

Records can include packet source addresses, AP-reported station identifiers,
supplied usernames, and verified identities. Supplied usernames remain
unverified even when an attempt succeeds. Verified names and security
identifiers come from the authentication result. The normal timeline does not
copy the full groups-and-claims snapshot.

Passwords, authentication proofs, shared secrets, private keys, and decrypted
authentication payloads are excluded. Unknown diagnostic fields are refused
by the emitter's schema guard. This interface provides no packet dump.

A field absent from eventd's response is unavailable. The reader cannot tell
whether it was never recorded or withheld. It does not recover missing fields
through configuration or a more privileged query.

## Loss, bounds, and retention

A missing terminal event leaves the outcome unavailable. Late evidence can
complete a timeline. Disconnected streams show their state immediately,
reconnect with overlapping history, and deduplicate records. Reader renewal,
limited backfill, collection loss, and missing stage sequences can leave gaps.
Old results retained during a failed reconnect are marked disconnected.

Finite queries publish no result if eventd fails before confirming completion.
An empty successful query means no matching readable records were returned.
It does not prove that no connection was attempted.

Requests discarded before conversation allocation have separate aggregate
reports, with bounded recent samples. Client matching is not proof of request
integrity. An integrity failure does not prove a wrong shared secret.

Registry values beginning with `Diagnostics` under
`Machine\Software\Radius\Settings` control emission and reader bounds. Consult
`radiusd.regman` for defaults and valid ranges. Client bounds limit retained
records and payload bytes; decoded frames and collection structures require
additional memory. eventd applies its own query resource limits independently.

Emission reserves capacity for final summaries, without guaranteeing delivery
under overload. Collection reports expose emission failures, local rate
suppression, and records omitted by emission policy. These reports are also
best effort. Missing reports leave collection state unconfirmed.

eventd controls persistent retention and field permissions. RADIUS does not
maintain an independent retention database or replay deleted evidence.
