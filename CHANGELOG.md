# Changes

## 0.2.3

- Statically link OpenSSL for the Intel macOS build to avoid a bundled library
  conflict at startup. Include the VPN changes listed below for 0.2.2.

## 0.2.2 (unpublished)

- Prefer UDP on compatible legacy gateways. Fall back to TLS on negotiation,
  probe, or liveness failures using the existing authentication session.
- Show the active data transport and record socket send backpressure in diagnostics.
- Handle legacy gateway kickout messages and preserve the source checkout when
  restarting as administrator on Windows.

## 0.2.1

- Hide to the system tray on window close while keeping VPN sessions running;
  retain normal minimize behavior. Add tray restore/disconnect-all/exit actions,
  a main-window exit button and Ctrl+Q, with cleanup completed before exiting.
- Keep the window accessible when the tray is unavailable, restore it for
  authentication prompts, and retain aggregate status in the tray icon/tooltip.
- Show a green checked connected button, connection status panel, elapsed time,
  per-profile status icons, and an aggregate connection count/window icon badge.
- Show connection/verification/disconnection progress and degraded-link warnings.
  Preserve failure reasons after cleanup, clear stale adapter details, and ignore
  delayed events from earlier connection attempts.
- Add offline Qt interaction and rendering regressions for connection feedback.

## 0.2.0

- Merge PR #1: keep the macOS Qt interface in the logged-in user session and
  request administrator authorization only for the utun/routes helper.
- Transfer the utun descriptor to the app and clean up routes when its helper
  control connection closes; retain the Windows adapter/elevation flow.
- Add optional password visibility, user Keychain support on macOS, and visible
  SMS-code entry. This targets the root-session input/startup problems; actual
  macOS launch, input methods and live VPN connectivity still need field testing.
- Include all 0.1.8 long-running tunnel and diagnostic improvements.

## 0.1.8 — long-running tunnel reliability

- Use TLS read/write readiness for retries and drain decrypted receive data in
  bounded batches. One session thread retains ownership of TLS sockets.
- Expire adapter packets stuck for 60 seconds, outbound packets queued for
  120 seconds, and incomplete frames stalled for 120 seconds. The existing
  30-second no-send-progress deadline remains. Healthy idle connections have
  no lifetime limit and are not periodically disconnected.
- Distinguish incoming tunnel traffic from actual inner-network packets so
  control heartbeats cannot hide a stalled data path.
- Enable TCP_NODELAY and OS TCP keepalive, with supported platform-specific
  keepalive tuning. Close tunnel sockets before bounded legacy logout I/O.
- Write diagnostics on a separate bounded worker queue. Slow/full disks no
  longer block the packet forwarding thread; dropped log events are counted.
- Add a unique run identifier, queue ages, partial-frame size, data/control
  receive ages and specific failure types to allowlisted diagnostics. Display
  queued bytes, adapter retries and diagnostic losses in the desktop UI.
- Add deterministic simulated 72-hour framing, repeated queue turnover,
  fragmented input, TLS retry, slow-disk and control/data health regressions.
  This does not replace real gateway soak or native macOS field testing.
- Do not add automatic authentication retries, undocumented heartbeat claims,
  credential retention, or changes to another active VPN connection.

## 0.1.7

- Persist allowlisted diagnostic events and traffic/queue counters in UTF-8
  rotating logs under the configuration directory (`logs/multi-vpn.log`,
  2 MiB per file and three backups). Passwords, tokens, certificates, raw
  packets, gateway addresses and account names are not recorded.
- Retry temporary Wintun/utun receive backpressure with a bounded queue instead
  of silently dropping packets. Report packets delivered to the adapter
  separately from packets received from the gateway and retry pressure.
- Show a degraded-link warning when outbound packets have had no incoming
  gateway data for 30 seconds; clear it on reception. Idle tunnels do not
  trigger this warning. This is not proof of heartbeat failure and does not
  automatically disconnect or reauthenticate.
- Bound the in-memory connection history to 500 entries and expose the
  diagnostic file location in the desktop UI.
- Add offline regression tests. Actual gateway throughput and long-running
  VS Code behavior still require authorized field validation.

## 0.1.4

- Fix Windows virtual IP readiness validation: check only the IP assigned to the
  new tunnel. Unusable APIPA/secondary addresses no longer cause false failures.
- Allow up to 30 seconds for the assigned address to become Preferred; a real
  duplicate address fails explicitly instead of being accepted.
- Report the assigned IP and actual address state on failure, replacing the
  generic PowerShell exception.
- Show the application version in the window title to distinguish installed and
  development builds.
- Add Windows regression tests and native acceptance using two simultaneous
  Wintun adapters. Tests use documentation-only addresses and never authenticate
  with a VPN gateway.
