# Release checklist

Use this checklist for the reviewed release commit. Record results in
[VERIFICATION.md](../VERIFICATION.md); previous release records are preserved in
[release checklist history](history/release-checklist-history.md) and
[release verification history](history/release-verification-history.md).

## Before release

- [ ] Confirm package, runtime, CLI, reports and Windows distribution versions agree.
- [ ] Update the changelog and check documentation and download links.
- [ ] Run the full regression suite on the supported Python matrix.
- [ ] Run Mypy and Ruff.
- [ ] Check branch-aware coverage is at least 80%.
- [ ] Run business scenarios and JSON / YAML example verification.
- [ ] Build wheel / sdist and run `twine check --strict` on both.
- [ ] Check packaged README / PyPI long description and distribution contents.
- [ ] Verify a fresh installation outside the source checkout.
- [ ] Build and smoke-test the Windows x64 portable ZIP; check its checksum.
- [ ] Record successful CI, CodeQL and Windows checks for the release commit.

Commands and verification scope are documented in [VERIFICATION.md](../VERIFICATION.md)
and [Windows portable](windows-portable.md).

## Release

- [ ] Merge the reviewed release changes and create the reviewed version tag.
- [ ] Create the GitHub Release from that tag.
- [ ] Attach the verified Windows portable ZIP and its `SHA256SUMS.txt`.
- [ ] Verify PyPI Trusted Publishing builds and publishes from the reviewed tag.
- [ ] Check the PyPI project page, version and long description.
- [ ] Confirm GitHub / PyPI versions, CLI output and Windows package metadata agree.

## After release

- [ ] Download the Windows ZIP from the public Release and verify its SHA256.
- [ ] Extract the full ZIP and run `Start-Demo.bat` as a normal user.
- [ ] Open the HTML report and check the printed report paths and Demo outcome.
- [ ] Check recovery evidence, restored mock data and local server shutdown.
- [ ] Test the published Python package in a fresh environment.
- [ ] Verify public release, package and documentation links.
- [ ] Record known limitations and the environments actually tested.
