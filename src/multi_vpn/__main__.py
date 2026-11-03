import sys

if '--network-helper' in sys.argv[1:]:
    from .runtime import run_macos_network_helper
    sys.exit(run_macos_network_helper())

from .app import main
main()
