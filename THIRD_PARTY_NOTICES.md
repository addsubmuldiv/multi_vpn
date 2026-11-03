# Third-party components

Multi VPN is an independent application. Component names below identify their
authors and licenses; they do not imply affiliation or endorsement.

- **Qt / PySide6 / Shiboken6** — The Qt Company and contributors. The runtime
  uses the LGPLv3 option. Full LGPLv3 and GPLv3 texts are bundled. Qt libraries
  are shipped as separate dynamic libraries in the application directory; users
  may replace compatible libraries and debug their modifications. No restriction
  on reverse engineering for debugging such modifications is imposed here.
  Source: https://code.qt.io/cgit/qt/ and
  https://code.qt.io/cgit/pyside/pyside-setup.git/ . Exact installed versions are
  recorded in the bundled `licenses/COMPONENTS.txt`.
- **Python** — Python Software Foundation and contributors; PSF license.
  Source: https://www.python.org/downloads/source/ . License bundled.
- **keyring and its runtime dependencies** — upstream authors; their original
  distribution license texts are included in `licenses/`.
- **Wintun 0.14.1**, Windows only — WireGuard LLC; upstream prebuilt distribution
  terms are in `vendor/WINTUN-LICENSE.txt`, also bundled with the application.
  Source: https://www.wintun.net/ .
- **PyInstaller bootloader** — PyInstaller developers; GPL with the upstream
  bootloader exception permitting distribution of bundled applications under
  their own terms. Its original license/exception is bundled.

The application icon is a project-local vector design in `assets/icon.svg`.
No original vendor client executable, DLL, logo, account, or gateway configuration
is included in the installers. This notice does not grant rights in third-party
software beyond the corresponding upstream licenses.
