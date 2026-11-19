---
title: Session Controls
description: Reevaluate established access and send precise, durable Disconnect and CoA requests.
---

RADIUS session controls operate on the accounting ledger's exact connection
occurrences. They use [RFC 5176](https://www.rfc-editor.org/rfc/rfc5176.html)
Disconnect or Change of Authorization (CoA) packets. Authentication can run
without accounting; automatic session controls require its inventory.

Use the local CLI or the GXWI Accounting section:

```sh
radius accounting disconnect SESSION-GUID
radius accounting reauthenticate SESSION-GUID
radius accounting update SESSION-GUID
radius accounting reconciliation SESSION-GUID
radius accounting commands SESSION-GUID
```

These commands retain the original occurrence, NAS selectors, device source,
action, actor and configuration revision before sending. An AP-reported
username never establishes identity or selects another connection. Sessions
without precise NAS and session selectors cannot be controlled. Missing
verified identity also prevents automatic controls; manual Disconnect can
still terminate a precisely identified occurrence.

CLI and GXWI generate a request GUID. Automation can supply `--request-id ID`
and reuse it after a lost reply. The actor/request pair retains one command,
including terminal results; it cannot select another session or action. A
different deliberate action needs a new ID. Inspect command history before
repeating an operation whose reply was lost. Request IDs are not capabilities.

## Device capabilities

A client can reference a reusable `DynamicAuthorizationProfile` GUID. Its
record lives under `DynamicAuthorizationProfiles` and contains `Name`,
`Enabled` and a JSON `Definition`. CLI uses the `dynamic-profile` object;
GXWI calls these Session Control Profiles. A missing reference uses the
generic RFC 5176 profile.

Profiles declare bounded recipes for `disconnect`, `reauthenticate` and
`update-authorization`, optional station targeting, standard attributes and
vendor-specific encodings. They cannot run code, insert usernames as
selectors, or replace integrity, authorization, retries and replay handling.
NAS and Acct-Session-Id selectors remain mandatory. See the source definition
in `radius-accounting/src/dynamic.rs` for the complete validated schema.

`nas_selectors` chooses which recorded NAS attributes the profile transmits:
`ip-address`, `identifier`, and `ipv6-address`. Omitting it retains all
recorded NAS attributes. The list must be nonempty and contain no duplicates;
at least one selected attribute must exist on the recorded occurrence, or the
request is refused. For example, `"nas_selectors": ["identifier"]` uses only
the recorded NAS-Identifier. This changes the wire recipe, not the immutable
session target or destination. Acct-Session-Id and integrity remain mandatory.

The generic profile supports Disconnect and standard VLAN/Session-Timeout
updates. It does not claim fresh reauthentication. Clearing a VLAN override
has no universal CoA encoding; it needs an explicit device reset recipe or an
enabled fallback. A profile that advertises reauthentication must declare
`fresh_proof: true` after device qualification. RFC 5176 Authorize-Only is
reauthorization and cannot serve as that declaration.

Every request carries Message-Authenticator and Event-Timestamp. Profiles
default to `"proxy_state_nonce": true`, adding an opaque Proxy-State nonce.
Set it to false only for a NAS that rejects that attribute; durable request
allocation still applies. Responses must match the packet family, identifier,
peer, and request authenticator. Requiring a response Message-Authenticator
is configurable for
NAS compatibility. Do not advertise a device-specific recipe as qualified
until it has produced a fresh authentication exchange on that device.

Before a new request can be transmitted, the ledger reserves its timestamp
and identifier atomically with the prepared packet. The pair never moves
backwards on the machine, even after a daemon restart, accounting
rebuild, history expiration or clock rollback. Retransmissions reuse the
original committed packet. An old ACK cannot authenticate a later request
using a different reserved pair.

`identifier_reuse_seconds` controls the NAS duplicate-detection window,
defaults to 300, and accepts 1–86400 seconds. Match it to the device's window.
At most 256 new requests can be sent to one NAS address within that
window; retries reuse their original reservation. Exhaustion or clock
rollback leaves requests pending, with a waiting reason, until a valid pair
is available. Other NAS addresses have independent reuse windows. The global
pair allocator permits up to 256 new requests per second across all NAS
addresses, preventing reuse when a destination or shared secret changes.
No timestamp is moved into the future to work around exhaustion. This follows
the identifier and replay constraints in [RFC 5176](https://datatracker.ietf.org/doc/html/rfc5176#section-6.3).

The allocator is retained in ledger format 3 and seeded from stored packets
when upgrading formats 1 or 2. Take a full offline state backup before the
upgrade; earlier daemons cannot open the upgraded ledger. Ordinary evidence
rebuild and retention do not erase the allocator.

For a NAS that rejects Proxy-State, a Disconnect-only compatibility profile
can retain all recorded NAS selectors and require the recorded station:

```json
{
  "version": 1,
  "name": "Disconnect without Proxy-State",
  "proxy_state_nonce": false,
  "station_selector": true,
  "require_station": true,
  "recipes": [
    {"action": "disconnect", "fresh_proof": false, "attributes": []}
  ]
}
```

On the development UniFi AP, the generic request received an authenticated
NAK with Error-Cause 401. Omitting only Proxy-State produced an authenticated
ACK, an accounting Stop and a new session with fresh password proof. This
also worked automatically when changing the assignment to VLAN 20 and back
to no override. This qualifies Disconnect on that tested device; it does not
establish CoA update, other firmware behavior or a DHCP address change.

In the observed iPhone trial, the address eventually changed to the VLAN 20
subnet after Disconnect and fresh authentication. On the return to no
override, the phone still displayed its old address after five minutes.
Explicitly assigning the main VLAN also failed to produce a new address and
connectivity was lost. Automatic DHCP renewal on VLAN changes is therefore
not qualified by this test. A successful Disconnect and new password proof
do not establish that the client has usable IP configuration.

## Automatic behavior

With accounting enabled, automatic session controls default on. The defaults
disconnect a session after its effective VLAN assignment changes or current
access is revoked, and request fresh authentication after password
replacement.
Automatic CoA authorization updates have a separate switch, default off.
Disabling VLAN-change Disconnect therefore does not implicitly select CoA.

Each access policy can override the defaults through `SessionControl` JSON.
Omitted members inherit their global values. GXWI exposes the overrides as
ordinary selectors under Access Policies:

```json
{
  "vlan_disconnect": true,
  "revoke_access": true,
  "password_reauthenticate": true,
  "update_authorization": false,
  "unavailable_grace_seconds": null,
  "fallback": []
}
```

`null` outage grace keeps existing connections and retries. A positive grace
can disconnect when current identity evaluation remains unavailable. The
timer persists across daemon restart and accounting rebuild. This requires
an active, valid control configuration; invalid or pending configuration
pauses controls as well as new successful admissions.

Reconciliation uses the original verified SID with current account status,
permitted claims, groups, Connect permissions, and assignment rules. It never
turns missing or withheld information into a grant or confirmed deletion.
Available, authorized lpsd change events are hints; periodic fresh reads cover
missed events, other sources, and restarts. Rapid hints coalesce without
continually restarting an unfinished inventory scan. Rules and shared-profile
effects use the same activation path as direct Registry edits. Renames and
unchanged effective decisions do not create session-control requests.

Only successfully activated configuration can authorize a command. A bounded
worker rechecks queued intent and retries against fresh identity state, away
from the UDP loop. Changed policy can supersede unsent commands. A transmitted
command whose relevance is lost remains uncertain: it might already have
acted.
An old occurrence's command is never redirected to a new roaming occurrence.

## Evidence and outcomes

The ledger keeps issued authorization, desired current authorization, and
device-reported observations separate. A recorded no-VLAN-override is an
explicit issued decision. No baseline means unknown, including sessions from
older ledger versions. Missing NAS observations do not imply an applied VLAN.

Successful authentication also binds an opaque credential reference and
revision. Password, MSCHAPv2, and NTLMv2 share the local password revision.
Replacement rotates it; NT-hash backfill and storage maintenance do not.
Current lookup can detect change or ineligibility, but only successful fresh
authentication can advance the revision proved by a session. RADIUS receives
no stored password hash or private key through this metadata.

The command history distinguishes pending, sent, acknowledged, rejected,
unsupported, uncertain, and superseded outcomes. Retries retain the exact
packet across restart. Only an explicit unsupported capability permits a
configured fallback; timeout, permission refusal, missing selectors, and a
missing session do not. The default fallback reports failure. Allowed fallback
order is update, then fresh reauthentication, then Disconnect; configure only
the steps desired.

An ACK records NAS acceptance. It does not establish fresh proof, a Stop
report, reconnection, DHCP renewal, or working applications. A phone can
retain an old lease after a VLAN change. Qualify reconnection and address
renewal separately on each AP/client combination.

## Configuration and permissions

Global controls are under `Machine\Software\Radius\Settings`. Individual
DWORDs override the corresponding `DynamicAuthorizationSettings` JSON member.
Unknown JSON members and out-of-range values prevent activation. GXWI exposes
the same controls; CLI uses `radius config set NAME=VALUE`.

The `radiusd.regman` reference owns each value's type, default, and bounds.
Controls include the scan interval and batch/work limits, identity-read
timeout, retry count and delay, command lifetime, maximum concurrent requests,
response-integrity requirements, and each automatic trigger. One identity
read can complete after the scan's work budget; its own timeout still bounds
that read.

`DynamicAuthorizationFallback` is REG_MULTI_SZ, empty by default. It accepts
`reauthenticate`, `disconnect`, or both in that order. For example, an
explicit
`disconnect` fallback lets an unsupported fresh-authentication request fall
back to terminating that occurrence. It does not bypass permissions.

Accounting SD rights add Reauthenticate (`0x40`) and Update Authorization
(`0x80`) alongside Disconnect (`0x8`). Read and Personal remain independent.
Manual requests need Read and the action right, plus every configured fallback
right, under the actual caller's token. Authorization is captured when the
durable request is submitted. Automatic requests identify radiusd as their
origin and are limited to enabled policy enforcement. Existing custom
descriptors retain their existing grants; review them before delegating new
actions. Packet bytes and shared-secret fingerprints are not returned by the
management interface.

## Upgrade and rollback

Ledger schema 2 adds control state while preserving usage, observations,
corrections, and command history. Older sessions keep unknown baselines until
fresh authentication. Rebuild preserves outage timers and command history and
does not resend commands as a side effect. Stable reevaluations do not fsync a
heartbeat on every scan. Schema 3 adds the durable wire allocator described
above, preserving that control state.

The matching lpsd uses store format 7 and persists credential bindings before
exposing an upgraded store. Preserve offline copies of both stores, their
security metadata, the prior configuration, and the prior runtime before a
live upgrade. Older binaries cannot read these newer formats. An older
development Registry can also need the `DynamicAuthorizationProfiles`
collection provisioned with the existing parent's permissions; fresh
`radius config init` creates it.

Host regression checks do not qualify an AP's fresh-authentication behavior,
VLAN reset conventions, DHCP renewal or roaming timing. Keep device-specific
qualification evidence separate from protocol and ledger tests.
