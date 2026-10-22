#!/usr/bin/env bash
# Rewrites the upstream module path to the fork's module path in go.mod and
# every Go import. Idempotent; run from anywhere inside the repository.
#
# The fork regenerates this commit on each upstream sync instead of rebasing it,
# so upstream changes to import blocks never conflict with the rename.
set -euo pipefail

OLD=github.com/refraction-networking/utls
NEW=github.com/roachadam/utls

cd "$(git rev-parse --show-toplevel)"

go mod edit -module "$NEW"

git ls-files -z -- '*.go' |
	xargs -0 perl -pi -e "s{\"\Q$OLD\E(/|\")}{\"$NEW\$1}g"

if git grep -n --fixed-strings "\"$OLD" -- '*.go'; then
	echo "rename-module: references to $OLD remain" >&2
	exit 1
fi
