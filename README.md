# Browse Safe

Browse Safe is a small Windows utility that inspects local network configuration, the Chrome browser and its extensions, and other system indicators that can affect safe browsing. It surfaces recent changes, unsigned drivers/services, suspicious startup items, and provides quick links to Windows Security and external analysis sites.

## Key features
- Safety Scan: runs a set of configurable network and system checks (DNS, hosts file, proxy, time sync, Windows Security state).
- Chrome inspection: shows executable integrity and enabled extensions with version/manifest info.
- Process, Services, Startup, Installed programs and Devices views with sortable grids and scan actions (signature verification, VirusTotal lookup).
- Quick Windows Security shortcuts in the left panel.
- Email report builder (opens Gmail in Chrome) for sharing scan results.
- Light / Dark theme toggle and theming applied across the app and embedded HTML view.

## Usage
- Build with Visual Studio or `dotnet build` (requires .NET 10 / net10.0-windows).
- Run BrowseSafe.exe; the app auto-runs the Safety Scan on first show.

## Packaging / CI
- A GitHub Actions workflow (.github/workflows/publish.yml) builds and publishes a Release artifact (zip) for win-x64.
- A helper script `common/set-version.ps1` updates project files, tags and pushes releases (supports `--dry-run`).

## Screenshots
Place sample screenshots in a `screens/` directory to have them displayed here. Two example assets included in the repo are shown below:

![Theme toggle icon](dark-light.png)
![Brand animation](landenlabs.webp)

## Contributing
PRs welcome. See the code comments and the `common` scripts for release/versioning conventions.

## License
See LICENSE in the repository root.
