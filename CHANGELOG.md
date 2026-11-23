# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0] - 2026-11-23

### Fixed
- Removed redundant `.to_string()` calls in `traverse_xml_tree` comparison to resolve Clippy `cmp_owned` warnings.
- Updated `to_hstring` call to match the `windows` 0.62 API change.

### Changed
- Upgraded `base64` from `0.22.1` to `0.23.1`.
- Upgraded `reqwest` to `0.13`.
- Upgraded `windows` crate to `0.62`.

### Added
- `anyhow` for improved error handling.
- Build-time webhook URL support.
- Unit tests.

### Security
- Fixed a memory leak in WLAN handle cleanup.

---

## [0.2.0] - 2024-07-02

### Added
- Webhook support to send results to a configured endpoint.
- `--nosend` flag to skip webhook transmission.
- Output filename argument to save results to a file.
- Expanded help menu text.

### Changed
- Stripped symbols and debug info from release builds.
- Improved output formatting and spacing.

### Fixed
- Newline formatting in terminal output.

---

## [0.1.0] - 2024-07-02

### Added
- Initial release.
- Enumerate saved Wi-Fi profiles on Windows using the WLAN API.
- Extract plaintext passwords for WPA2, WPA2PSK, and WPA3SAE networks.
- Report open networks with no password.
