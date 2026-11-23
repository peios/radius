---
title: Access Assignment
description: Select a complete network access profile using PNP-style rules, typed identity facts, and explicit defaults.
---

Each access policy owns a forest of assignment rules. A successful decision
selects one complete access profile. Profiles are shared objects with stable
GUIDs; renaming a profile preserves its references.

Assignment supplements authentication, Connect permissions, and accounting
allowances. All gates must permit access before radiusd sends success or keys.
Authd supplies identity and permitted claims; it does not interpret VLANs.

## Profiles and defaults

An access profile contains `Name`, `Enabled`, and optional typed network
settings described in [Access Profile Settings](~peios/reference/radius/access-profile-settings).
These include timers, rates, filters, addressing, tunnels, and equipment
extensions. The optional `VlanId` is a DWORD.
VLAN IDs range from 1 through 4094. An absent `VlanId` produces no VLAN
override. Zero is invalid. Disabling a selected profile refuses admission.

Profiles live under `Machine\Software\Radius\AccessProfiles\<guid>`. Rules
live under `AccessPolicies\<policy-guid>\Rules\<rule-guid>`, relative to the
same RADIUS root. Child rule keys are exceptions to their parent rule. `Name`
is a display label. Rule keys use canonical UUIDv4 identities.

No selected profile means refusal. An explicit catch-all rule can select a
default profile, including a profile with no VLAN override. Parent rules do
not merge settings into the selected profile.

```sh
radius access-profile create Staff --set VlanId=20
radius access-profile create Default
radius rule create Default --set Policy=POLICY-GUID \
    --set 'Actions=ASSIGN(DEFAULT-PROFILE-GUID)'
radius rule create Staff --set Policy=POLICY-GUID --set Parent=DEFAULT-RULE-GUID \
    --set Subject.Group.Equal=S-1-5-32-545 \
    --set 'Actions=ASSIGN(STAFF-PROFILE-GUID)'
```

Replace the GUID placeholders with identities returned by the creation
commands. A nested `Parent` uses slash-separated ancestor GUIDs. `Policy` and
`Parent` are derived management fields; direct Registry edits do not store
them as rule values. A rule's location remains fixed after creation.

Remove a VLAN override with `radius access-profile unset PROFILE-GUID VlanId`.
Use `radius rule unset RULE-GUID CONDITION-KEY` to remove a condition, or
`radius rule unset RULE-GUID Priority` to restore inherited priority. Deleting
an object with references is refused.

GXWI provides Access Profiles, Assignment Rules, and Explain Policy sections.
The rule editor exposes actions, profiles, conditions, and parent selection.
Shared-profile references appear in the affected-object information.

## Rule evaluation

The evaluator shares PNP's tree traversal, ancestor fallback and collation.
Conditions on a rule are ANDed. Alternatives inside one condition are ORed.
Disabled rules hide their subtree. A matching child shadows its parent only
within that tree; independent trees still contribute candidates.

`Priority` is a signed decimal string or a DWORD. It inherits from the parent,
or defaults to zero at a root. `Actions` accepts a string or string list:

- `ASSIGN(profile-guid)` selects a complete profile.
- `REJECT` refuses admission.
- `NULL` abstains. The nearest ancestor with a direct decision speaks for
  that region, using the ancestor's priority.

The highest-priority candidate wins. At equal priority, `REJECT` wins over
assignment. Equal-priority assignments to the same profile agree. Different
profiles tied at the winning priority cause a per-connection refusal, with
both rule paths reported in operational diagnostics. Rule order has no effect
on permission. A single rule cannot select multiple different profiles.

## Facts and types

| Fact | Meaning and type |
|---|---|
| `Subject.User` | Authd-verified user SID |
| `Subject.Group` | Authd-disclosed enabled group SIDs; any-member matching |
| `Subject.Name` | Authd's canonical username; exact string |
| `Subject.Claim.<name>.<type>` | Disclosed claim; explicit native type |
| `Client.Id` | GUID of the configured client that verified the request |
| `Client.Address` | Actual packet source IP address |
| `Request.SSID` | Reported SSID bound to the selected access policy |
| `Request.Station` | AP-reported station MAC; not device authentication |

Condition value names append an operator, such as `Subject.Group.Equal` or
`Subject.Claim.Department.String.Equal`. Claim types are `Int64`, `Uint64`,
`Boolean`, `String`, `Sid`, and `Octet`. Claim names use the same
per-character Unicode lowercase equivalence as KACS and authd, without
normalization or full case folding. String values compare exactly.

`Equal` uses one scalar or a list. Signed integers and IP addresses use PNP's
pattern grammar; unsigned integers preserve the full 64-bit range and support
decimal inclusive ranges. Numeric facts support `GreaterThan` and `LessThan`
with one threshold. Boolean patterns use `true` or `false`; octet patterns use
even-length hexadecimal strings. MAC patterns use PNP's colon-separated form.
Runtime values never convert between strings, numbers, and booleans.

Unknown facts, unsupported operators, and malformed patterns invalidate the
configuration. A known fact missing from an authentication does not satisfy an
ordinary comparison. A value of an incompatible type does not match.

`Present = 1` tests known presence; `Present = 0` tests known absence. For
claims, filtered disclosure leaves omitted names unknown unless authd
explicitly confirms absence. Neither presence test matches an unknown claim.
Disabled and deny-only claims are unavailable to assignment comparisons and
cannot prove absence. Withheld claims do not become false, zero or empty.

## Configuration and established connections

Rules and profiles join the same short, consistent Registry snapshot as other
RADIUS configuration. Invalid, pending, or unreadable configuration pauses new
admissions and cached success replies. The status endpoint remains available
for repair; radiusd does not continue granting under an older policy.

The final authentication decision uses current policy. Semantic changes
invalidate cached acceptance replies. Existing Wi-Fi connections receive
another assignment when they next authenticate, including automatic
reauthentication. The AP controls how it applies a changed VLAN. Configurable
[Session Controls](~peios/reference/radius/session-controls) can act after successful
activation; VLAN-change Disconnect defaults on when automatic controls and
accounting are enabled. The exact issued baseline, current policy, and precise
session selectors determine which occurrences are affected.

A VLAN change does not assign the client's IP configuration. A client can
retain its previous DHCP lease after reauthentication and lose connectivity
until it disconnects and reconnects. Do not assume a live VLAN change is
seamless: qualify both the AP's assignment and the client's address renewal.
DHCP's [network-change guidance](https://www.rfc-editor.org/rfc/rfc2131.html#section-3.7)
describes address verification after disconnection. When testing a change,
check the client's address, gateway, and connectivity on both networks.

VLAN assignment uses the three tunnel attributes described in [RFC 3580
section 3.31](https://www.rfc-editor.org/rfc/rfc3580.html#section-3.31), with
a zero tag and a decimal VLAN string. radiusd signs the complete response,
including accounting Class and timeout attributes, before caching it.

## Explain saved policy

Explain Policy uses the same compiler and evaluator as admission. It shows
matching conditions, shadowed rules, ancestor fallback, priorities, competing
profiles, and the backstop. Explanations contain condition outcomes, not claim
values. Normal Registry permissions govern access to rules and profiles.

The CLI accepts typed hypothetical facts from a JSON file:

```json
{
  "values": {
    "Subject.Group": [{"type": "sid", "value": "S-1-5-32-545"}],
    "Subject.Claim.Department": [{"type": "string", "value": "Engineering"}]
  },
  "claim_coverage": "filtered",
  "absent_claims": []
}
```

```sh
radius --json policy explain POLICY-GUID --facts /path/to/facts.json
```

`claim_coverage` defaults to `filtered`. Set `complete` only when the
hypothetical input intentionally asserts a complete claim set. `absent_claims`
supplies known absences separately. GXWI exposes the same knowledge
distinction.

The result identifies saved configuration and its fingerprint. It does not
claim that the daemon activated that configuration. Simulation does not verify
credentials, run Connect checks, reserve allowances, grant access, or contact
an AP.

Supplying a single `Client.Id` fact compiles the selected settings with that
client's saved equipment mapping. The returned authorization plan separates
encoded settings from missing mappings and missing client context. Successful
encoding does not establish that a device supports or enforces the attributes.

## Bounds and development migration

The Registry loader accepts at most 1024 rules, 32 nested exception levels, 64
conditions per rule, 256 alternatives per condition and 4 MiB of rule values.
Profile count is bounded at 256. Hypothetical input has equivalent fact
bounds; the CLI file limit is 1 MiB.

Schema 3 requires explicit assignment rules. For a stopped schema 2
development deployment without assignment objects, the `migrate-policy-v3`
example prepares one default profile and a catch-all rule for each
authenticating policy. Running without arguments prints the candidate.
`--apply` creates the defaults and changes the schema in one Registry
transaction. It preserves credentials, existing records, and descriptors;
created keys inherit normal permissions. Do not edit RADIUS configuration
concurrently with this one-off migration. Keep the prior configuration and
runtime available for rollback.
