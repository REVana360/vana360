# Architecture

Vana360 includes one ReXGlue title, runtime compatibility hooks, and a login and lobby client.
The title starts at `GameExecContent0001.xex` and loads:

- `PolCoreContent.xex`
- `FFXi.dll`
- `FFXiMain.dll`
- `patch.xex`

## Code layout

Runtime compatibility hooks and the guest-facing lobby bridge are in `src/runtime/`.
Login protocol code is in `src/login/`, and native tests are flat under `tests/`.

ReXGlue generates guest C++ beneath ignored `generated/`.
Generated output is never edited or committed.

## Login and world handoff

The host bridge owns authentication and account session state.
It also owns the login data socket used to coordinate character listing and selection.
The guest retains the login view socket and the original client-side selection flow.

The bridge generates one 20-byte map-session key for both sides of the handoff.
It sends that key through the host data-selection request.
Before map login, it derives the guest's 16-byte map cipher from the same key.
This shared key is the boundary between the replacement lobby bridge and the original client.

## Replacement scope

Vana360 replaces PlayOnline only at the required host boundary.
That boundary covers authentication, character listing and selection,
map handoff, and world login.

## Server dependency

The maintained `REVana360/vana360-lsb` fork supplies the supported external server.
Its exact revision is in [the server lock](../vana360-lsb.lock.json).
Upstream LandSandBoat is not vendored; it remains the upstream reference for the
server's database, protocol, and gameplay.
