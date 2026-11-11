# Agent instructions for terraform-permcheck

This file is for coding agents that work in this repository. `CLAUDE.md` is a symlink to it.

## Releasing

A release is a pushed `v*` tag. The Release workflow runs GoReleaser, which publishes the GitHub release with its archives and `checksums.txt`. GoReleaser also pushes the Homebrew cask to `elecnix/homebrew-tap`. The workflow first checks that the tag matches the `version` constant in `main.go`, and it stops there when they differ.

1. Open a pull request that changes `const version` in `main.go` to the new version, such as `release: bump to v0.10.1`. Merge it after its checks pass.
2. Tag the merge commit of that pull request, not an earlier commit, and push the tag:

   ```bash
   git fetch origin
   git tag -a v0.10.1 -m v0.10.1 origin/main
   git push origin v0.10.1
   ```

3. When the Release run finishes, check that the release lists its archives and `checksums.txt`, and that `terraform-permcheck version` in a downloaded archive prints the tag.
4. Check that `brew install elecnix/tap/terraform-permcheck` installs the new version.

A pushed tag is final. The Go module proxy caches a tag the first time anyone fetches it, so deleting or moving the tag doesn't change what `go install` and the proxy serve. If a release run fails, fix the cause in a new pull request and release the next patch version. Never reuse a version.

The Homebrew upload needs the repository secret `HOMEBREW_TAP_SSH_KEY`, the private half of a deploy key with write access on `elecnix/homebrew-tap`. Without it, the run warns and publishes the release with no cask.
