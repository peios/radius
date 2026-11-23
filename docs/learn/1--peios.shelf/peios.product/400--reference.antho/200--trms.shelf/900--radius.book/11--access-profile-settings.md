---
title: Access Profile Settings
description: Typed network authorization, equipment mappings, complete replies, and the limits of live updates.
---

An access profile describes the network service a successful authentication
requests. Assignment rules select one complete profile; the receiving
equipment enforces its attributes. The shared `radius-authorization` library
validates logical settings, compiles the reply, and retains the association
between each setting and its wire attributes for later session controls.

## Setting families

Profiles cover connection timers, bandwidth and priority, VLAN memberships,
traffic filters and roles, gateway addressing and routes, tunnel parameters,
accounting preferences, and device administration. These are authorization
settings. Adding a gateway pool name does not add an address allocator;
device-administration settings do not add a device authentication
method. Authentication profiles and principal allowances remain separate.

The Registry interface is documented under
`Machine\Software\Radius\AccessProfiles\<guid>` in `radiusd.regman`.
Discover the same setting metadata used by CLI and GXWI with:

```sh
radius access-profile fields
```

An absent setting requests no override. An explicit false flag requests the
equipment's disabled value; it differs from absence. Unknown settings and
wrong Registry types invalidate configuration. `Extensions` is a JSON object
of typed, namespaced `Extension.<namespace>.<name>` values, with explicit
vendor mappings. It cannot override server-owned identity, selectors, keys,
EAP state, Class, or integrity fields.

Rates are per connection, in bits per second from the connected device's
perspective. Upload travels from the device; download travels to it. Bursts
are bytes. The decimal string representation preserves the complete unsigned
64-bit range. Minimum rates cannot exceed configured maximum rates. A minimum
rate requests an equipment capability; it does not reserve capacity in Peios
or enforce a principal-wide aggregate bandwidth limit.

`VlanId` is a numeric untagged assignment. `VlanName` and tagged or untagged
memberships use the distinct RFC 4675 attributes; they are not alternate
spellings of the numeric tunnel assignment. A numeric VLAN and a second
tunnel assignment cannot coexist. Named filters refer to filters installed on
the equipment. Explicit filter rules accept the supported NAS-Filter-Rule
grammar, with one complete rule per list item. Roles, isolation, QoS, and
IPv4 DNS need an explicit equipment mapping.

Addresses, canonical prefixes, routes, MTU, and tunnel parameters apply to
gateways that understand them. A route contains a destination, a gateway, and
an optional numeric metric. A prefix with host bits is refused. IPv4 netmasks
must be contiguous. Pool references do not allocate leases or control a
bridged Wi-Fi client's DHCP state. Management settings require an appropriate
management Service-Type; they do not grant a local Peios token.

`AccountingInterimSeconds` requests a NAS update interval of at least 60
seconds. It does not alter the ledger's durability rules. `ServiceLabel` is
retained local authorization metadata unless an explicit mapping also sends
it to the equipment. It never replaces the server's accounting correlation.

## Timers and allowances

RADIUS provides one Session-Timeout and its Termination-Action. Choose a
profile reauthentication interval, or a session timeout with a disconnect or
reauthenticate action. A session timeout defaults to disconnect. Configuring
both interval settings is refused because they cannot be independent wire
timers. Idle timeout is separate and concerns inactivity after admission; the
daemon's similarly named conversation timeout bounds the authentication
exchange itself.

The network's reauthentication cap can shorten the profile timer. Principal
allowances can shorten it again. The accounting proof retains the configured
cap separately from the shorter reply, so an allowance countdown does not
create repeated policy-change commands. Disconnect expiry does not prevent
another successful authentication. Use cumulative principal allowances for
limits that span multiple successful authentications.

## Configuring a profile

CLI and GXWI use the same validation and complete-profile selection:

```sh
radius access-profile create Guests --set VlanId=20 \
    --set IdleTimeoutSeconds=300 --set DownloadBitsPerSecond=10000000 \
    --set UploadBitsPerSecond=2000000
radius access-profile set PROFILE-GUID \
    --set 'FilterRules=["permit in 6 from any to assigned 80,443"]'
radius access-profile unset PROFILE-GUID DownloadBitsPerSecond
```

Replace `PROFILE-GUID` with the created identity. List input accepts a JSON
array when an item contains commas; simple lists also accept comma-separated
items. GXWI uses one list item per line. Clearing an optional field removes
the saved value. Saving still requires a valid complete profile; for example,
remove its expiry action when removing its associated session timeout.

The rate example requires an equipment mapping before admission can succeed.
A valid logical setting that cannot be encoded for the actual client refuses
the connection before quota reservation. It is never silently omitted.

## Equipment mappings

The client's existing `DynamicAuthorizationProfile` also supplies its
`authorization` mapping. Its definition contains three maps: `settings` for
admission encodings, `live` for qualified CoA settings, and `clear` for
explicit removal values. A missing setting uses its defined standard encoding.
An empty encoding list explicitly marks a setting unsupported. Vendor-only
settings have no guessed default. Encodings are bounded data, not executable
plugins.

Generate the WISPr rate template with:

```sh
radius dynamic-profile template wispr
```

GXWI offers the same template while creating a Session Control Profile. It
changes the draft only. The template encodes upload and download using vendor
14122 attributes 7 and 8. It declares no qualified live rate support. It is
an attribute template, not a claim that a particular AP enforces those rates.

A custom mapping can describe integer, boolean, text, address or prefix
encodings. Integer conversion uses an exact divisor: values that would round
or overflow are refused. Text and decimal-text encodings can add bounded
prefixes and suffixes. For example, a synthetic equipment definition could
contain:

```json
{
  "authorization": {
    "settings": {
      "DownloadBitsPerSecond": [
        {
          "target": {"vendor": 12345, "attribute": 1},
          "format": "decimal-text",
          "divisor": 1000,
          "prefix": "rate=",
          "suffix": "k"
        }
      ]
    },
    "live": [],
    "clear": {}
  }
}
```

This is the authorization portion of a full Session Control Profile
definition. It is not a recipe for real equipment. Standard type checks,
protected targets, conflicting attribute owners, and the complete reply budget
apply to every mapping. A reply accepts at most 96 authorization attributes
and 2400 encoded bytes; credentials and protocol fields remain server-owned.

## Explaining and changing established access

Explain Policy shows the selected logical settings. Supplying a single
`Client.Id` fact also compiles an authorization plan with that client's saved
mapping. The plan distinguishes unsupported settings and missing client
selection. It does not authenticate, check every admission gate, send a
packet or prove enforcement. Operational diagnostics record an assignment
fingerprint over the selected VLAN and complete compiled authorization,
without adding raw filter or extension values to events.

An automatic or manual CoA compares complete authorization settings. Changed
settings need declared live support. A removal needs an explicit reset of the
original recorded attribute; omission never means reset. A changed attribute
identity requires fresh authentication. Management protocol and transport
protection changes cannot be sent in CoA. Equipment that replaces an entire
list must be qualified for that replacement behavior.

A recipe that cannot express the new authorization uses the existing
configured fallback and its separate permissions. An ACK records what was
requested and acknowledged, not proof that every setting was enforced. The
issued baseline, desired settings, last acknowledged request, and limited NAS
observations remain distinct. See
[Session Controls](~peios/reference/radius/session-controls).

## Storage and qualification

Ledger format 4 retains logical settings, exact per-setting encodings,
configured timer caps, and previous acknowledged authorization for commands.
It upgrades formats 1–3 without inventing missing legacy settings. Back up
the complete stopped ledger and prior runtime before upgrading: earlier
daemons refuse format 4. Registry schema remains 3; older readers refuse
unknown profile fields rather than grant a partial assignment.

Deterministic tests check encoding vectors, reply authenticators, protected
fields, unsupported mappings, policy selection, quota gating, retransmission,
reset handling, persistence, and frontend representations. These checks cannot
establish traffic shaping, ACL enforcement, gateway addressing, or device
administration on untested equipment. Qualify each required field on the
actual NAS and firmware before relying on its enforcement.

The underlying attribute definitions are in
[RFC 2865](https://www.rfc-editor.org/rfc/rfc2865.html),
[RFC 3580](https://www.rfc-editor.org/rfc/rfc3580.html),
[RFC 4675](https://www.rfc-editor.org/rfc/rfc4675.html),
[RFC 4849](https://www.rfc-editor.org/rfc/rfc4849.html),
[RFC 6911](https://www.rfc-editor.org/rfc/rfc6911.html), and
[RFC 5607](https://www.rfc-editor.org/rfc/rfc5607.html).
