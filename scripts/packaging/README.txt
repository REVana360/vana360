Vana360

Vana360 is a Windows x64 native recompilation of the Xbox 360 release of Final
Fantasy XI, using the ReXGlue runtime and an external LandSandBoat server.

PACKAGE CONTENTS

This archive contains the Vana360 executable, generated guest modules, and the
ReXGlue runtime libraries. build-info.json identifies the exact public
title and SDK inputs used for this package. It intentionally contains no game
data, generated source, retail executable, DAT files, or ISO image.

REQUIREMENTS

Windows 11 x64 and a Direct3D 12 capable GPU are required. Use only legally
owned content from the supported 2009 Ultimate Collection USA disc. The package
does not include that content or a game server.

FIRST RUN

1. Extract the entire archive.
2. Prepare a local folder containing game data extracted from your legally
   owned supported disc.
3. Launch revana.exe with --game_data_root=<path-to-game-data-root>.
4. Keep game data outside the application archive and do not add it to Git.
5. User data and shader caches default to Documents\My Games\REVana360.
   Use --user_data_root and --cache_root only when overriding that location.

NETWORKING

Vana360 connects to an external LandSandBoat server when all required lobby
variables are set:

- REVANA_LOBBY_HOST
- REVANA_LOBBY_USERNAME
- REVANA_LOBBY_PASSWORD
- REVANA_LOBBY_CLIENT_VERSION

Ask the server operator for its required ten-byte client version, including
the underscore and revision suffix. It must match the server configuration.

Optional lobby variables configure the corresponding login transport values:

- REVANA_LOBBY_OTP
- REVANA_LOBBY_AUTH_PORT
- REVANA_LOBBY_DATA_PORT
- REVANA_LOBBY_VIEW_PORT
- REVANA_LOBBY_CERTIFICATE_SHA256

DIAGNOSTICS

REVANA_TRACE_STARTUP=1 enables guest startup and runtime tracing.
REVANA_LOBBY_STATE_TRACE=1 enables lobby state-change tracing. Diagnostic logs
can contain runtime details and must be kept private. SDK socket metadata
tracing is separately opt-in through --guest_network_trace=true.

LEGAL

Use only game content you legally own. See LICENSE.txt and the licenses folder
for project and third-party software notices.
