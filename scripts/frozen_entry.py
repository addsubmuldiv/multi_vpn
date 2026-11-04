import sys

if __name__=='__main__':
    if '--network-helper' in sys.argv[1:]:
        from multi_vpn.runtime import run_macos_network_helper
        sys.exit(run_macos_network_helper())
    from multi_vpn.app import main
    main()
