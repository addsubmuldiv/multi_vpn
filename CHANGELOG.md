# Changes

## 0.1.6

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
