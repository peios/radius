---
title: Administration
description: Manage RADIUS clients, policies, methods, certificates, and local service state through the CLI or GXWI.
---

The `radius` program provides terminal administration and a GXWI window:

```sh
radius --window
```

Both interfaces use the same management library and the caller's actual
permissions. Configuration is stored directly in the local Registry, so
editing works while radiusd is stopped. The daemon's local status endpoint is
read-only. There is no remote management listener. Use an SSH session for a
remote CLI; a GXWI desktop can present the window remotely.

## Configuration objects

The window groups authentication, assignment, and accounting administration
into separate sections. Overview reports service and configuration activation
state.

Overview's listener field starts with the saved addresses. Background
refreshes follow external changes while the field is unchanged, preserving an
edit in progress. The saved value shown below the field remains separate from
the draft.

| Object | Purpose |
|---|---|
| Client | Source addresses, shared secret, and allowed policies |
| Access policy | Exact SSID, Connect permissions, profile, and reauthentication |
| Authentication profile | Ordered allowed methods and server identity |
| Server identity | Named certificate chain and matching private key |
| Access profile | Complete assignment settings, including an optional VLAN |
| Assignment rule | Policy-owned conditions, action, priority, and exceptions |
| Session control profile | Reusable device capabilities for Disconnect and CoA |

Objects have immutable GUIDs. Names are editable labels and can be duplicated;
an ambiguous CLI name requires a GUID. References always use GUIDs. Renaming
preserves references. Deleting and recreating an object creates a new GUID.
Management refuses deletion while another object refers to the target and
shows its dependents. It never cascades deletion.

Use these commands to inspect the current objects:

```sh
radius status
radius client list
radius policy list
radius profile list
radius identity list
radius access-profile list
radius rule list
radius dynamic-profile list
radius config check
```

`radius --help` lists commands. `--json` produces structured output, including
GUIDs and typed errors. Exit status is 0 for success, 64 for invalid
arguments, 3 for denied permission, 4 for a missing object, 5 for invalid
configuration, and 1 for other failures. Explicit secret output is raw bytes
and does not accept `--json`.

See [Access Assignment](~peios/reference/radius/access-assignment) for profile
selection, rule editing, explicit defaults and hypothetical policy
explanations.

The Accounting section exposes exact-session Disconnect, fresh
reauthentication, authorization updates, and command history. Each action has
an independent Accounting security descriptor right; configuration-write
access alone does not grant control of established sessions. See
[Session Controls](~peios/reference/radius/session-controls) for activation,
device capabilities, fallback permissions, and outcome interpretation.

## Initial setup

`radius config init` initializes an absent configuration with schema version
2, empty object collections, and a UDP listener at `0.0.0.0:1812`. It refuses
an existing deployment. The empty configuration admits nobody. Configure the
service identity, authd capability, and port reservation separately as
described in [Native Integration](~peios/reference/radius/native-integration).

Create a server identity first, then a profile, policy, and client. In the
window, reference pickers show object names and retain their GUIDs. CLI
references use the GUID returned by a create or list command. For example:

```sh
radius identity create Main \
    --set CertificateFiles=/path/server.pem,/path/intermediate.pem \
    --set PrivateKeyFile=/path/server.key
radius profile create Passwords \
    --set AuthenticationMethods=peap-mschapv2,ttls-pap \
    --set ServerIdentity=IDENTITY-GUID
radius policy create Household --set SSID=Home \
    --set AuthenticationProfile=PROFILE-GUID \
    --set 'ConnectSecurity=O:SYG:SYD:(A;;0x1;;;HOUSEHOLD-GROUP-SID)'
radius client create AccessPoints --set Addresses=10.10.0.0/16 \
    --set Policies=POLICY-GUID
```

Replace the placeholder GUIDs and group SID with actual values. Source
addresses must be canonical literal addresses or prefixes. The first
authentication method is preferred. Credential rejection does not cause
fallback to another method. PEAP/MSCHAPv2 requires matching authd credential
support; enabling it in a profile does not change authd's password policy.

The client receives a generated 48-character shared secret. Explicitly reveal
it and configure the same value on the corresponding RADIUS client:

```sh
radius client secret AccessPoints show
```

The window similarly requires an explicit reveal. Normal lists, records,
status, and errors contain no secret contents. Reveal still requires read
permission on the protected file. Supply your own secret using an echo-free
prompt, standard input, or a file; avoid placing secrets in process arguments:

```sh
radius client secret AccessPoints set
radius client secret AccessPoints set --file /protected/shared-secret
radius client secret AccessPoints generate
```

A generated replacement also needs updating on the corresponding client. The
policy's reauthentication interval defaults to 3600 seconds.

## Permissions and credentials

Connect permissions decide whether an authenticated subject can use a policy.
Management permissions are the ordinary Registry key descriptor controlling
who can edit it. The window opens the existing security descriptor editor for
each, under separate controls. The CLI exposes their descriptors without a
separate permission language:

```sh
radius policy permissions Household connect
radius policy permissions Household management
```

Add an SDDL argument to set a descriptor. Configuration-write rights,
credential-file read rights, service-control rights, and local-status query
rights remain independent. The default status descriptor permits SYSTEM and
Administrators. An explicit `Settings\StatusSecurity` can change that policy;
malformed or unreadable explicit values deny queries. The endpoint checks the
kernel-attested peer token, including deny-only groups.

Certificate import accepts PEM or DER and verifies that the key matches the
leaf certificate. The window shows certificate subject, issuer, DNS names,
validity dates, and fingerprint. Import paths refer to files on the Peios
machine, including when the window is presented remotely. The program does not
issue certificates or replace a CA. Replacing an identity preserves its GUID
and dependent profile references:

```sh
radius identity inspect Main
radius identity import Main --set CertificateFiles=/path/new-chain.pem \
    --set PrivateKeyFile=/path/new-key.pem
```

Shared secrets and keys are staged as new protected files before Registry
references switch in a transaction. Failed saves remove their new files.
Successful replacement retains old files until they can safely be removed;
deleting a record does not erase credential files automatically.

## Saving, activation, and recovery

Saving updates stored configuration. It does not claim the daemon activated
it. Overview shows saved and effective fingerprints and activation issues. The
daemon independently validates direct Registry edits. A broken reference, bad
descriptor, or unreadable credential pauses admissions until repaired; the old
policy is not silently kept active. The local status endpoint remains
available even when initial configuration is invalid.

The tools preserve malformed records for inspection and repair. Direct
Registry editing can bypass deletion safeguards. Related management writes are
transactional; there is no stale-form conflict detection.

Disabled clients, policies, and profiles deny affected admissions while
unrelated valid policy continues. A disabled shared profile affects every
policy using it; the window shows those dependents before confirmation.
Established stations are not immediately disconnected by these edits.

Service controls are separate from object state:

```sh
radius service stop
radius service start
radius service restart
radius service boot on
radius service boot off
```

Commands report submission; check status for completion. Boot preference does
not start or stop the current process. Stop and restart interrupt ongoing
authentication; existing network access can continue until reauthentication.
Routine edits reload without a service restart. No command requires a kernel
rebuild.
