# Changes

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
