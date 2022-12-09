# Release instructions

## Pre-release checks

These should run successfully:
* `go test ./...`;
* `golangci-lint run ./...`;
* `go fmt ./...` (should not change any files);
* `go mog tidy` (should not change any files);
* `./prepare.sh /path/to/frostfs-api/on/your/machine` (should not change any files).

## Writing changelog

Add an entry to the `CHANGELOG.md` following the style established there. Add an
optional codename(for not patch releases), version and release date in the heading.
Write a paragraph describing the most significant changes done in this release. Add
`Fixed`, `Added`, `Removed` and `Updated` sections with fixed bug, new features and
other changes.

Open Pull Request (must receive at least one approval) and merge this changes.

## Update README

Actualize compatibility table in `README.md` with relevant information.

## Tag a release

Use `vX.Y.Z` tag for releases and `vX.Y.Z-rc.N` for release candidates
following the [semantic versioning](https://semver.org/) standard.

Update your local `master` branch after approved and merged `CHANGELOG.md` changes.
Tag a release (must be signed) and push it:

```
$ git tag -s vX.Y.Z[-rc.N] && git push origin vX.Y.Z[-rc.N]
```

## Make a Github release

Using Github's web interface create a new release based on just created tag
with the same changes from changelog and publish it.

## Close github milestone

Close corresponding vX.Y.Z github milestone.
