#!/usr/bin/env bash
# Rebuilds the fork's patch stack on the newest upstream commit.
#
#   .fork/sync-upstream.sh [FORK_REF] [UPSTREAM_REF] [BRANCH]
#   .fork/sync-upstream.sh --continue
#
# The stack is every non-merge commit on FORK_REF that is not in upstream and
# not in the previous stack's history. On BRANCH, it regenerates the module
# rename with rename-module.sh, cherry-picks the rest in order, and drops
# patches that upstream already contains. It ends with a merge commit whose
# parents are FORK_REF and the new stack and whose tree is the new stack's, so
# merging BRANCH into main never rewrites history. The merge commit message
# links the upstream changes for review and lists go.mod changes.
#
# Prints "up to date" and creates nothing when FORK_REF already contains
# UPSTREAM_REF. On a cherry-pick conflict it stops; resolve the conflict, stage
# the files, and run it again with --continue.
set -euo pipefail

RENAME_SUBJECT="Change module path to github.com/roachadam/utls"

cd "$(git rev-parse --show-toplevel)"
state="$(git rev-parse --absolute-git-dir)/sync-upstream"

if [ "${1:-}" = "--continue" ]; then
	if [ ! -d "$state" ]; then
		echo "sync-upstream: nothing to continue" >&2
		exit 1
	fi
	if git rev-parse --verify --quiet CHERRY_PICK_HEAD >/dev/null; then
		git -c core.editor=true cherry-pick --continue
	fi
	git log -1 --format=%s "$(cat "$state/current")" >>"$state/applied"
else
	FORK=${1:-origin/main}
	UPSTREAM=${2:-upstream/master}
	BRANCH=${3:-sync/upstream}

	# Untracked or modified files would otherwise be committed into the stack.
	if [ -n "$(git status --porcelain)" ]; then
		echo "sync-upstream: working tree is not clean" >&2
		exit 1
	fi

	fork=$(git rev-parse "$FORK^{commit}")
	upstream=$(git rev-parse "$UPSTREAM^{commit}")
	base=$(git merge-base "$fork" "$upstream")
	if [ "$base" = "$upstream" ]; then
		echo "up to date with upstream ${upstream:0:12}"
		exit 0
	fi

	# The previous stack's history is reachable from the first parent of the
	# last sync merge. Upstream history is excluded from the search, so an
	# upstream commit carrying the trailer cannot pose as one.
	exclude=("^$base")
	last_sync=$(git log --merges --grep='^Upstream-Sync: ' --format=%H -1 "$fork" "^$upstream")
	if [ -n "$last_sync" ]; then
		exclude+=("^$last_sync^1")
	fi

	rm -rf "$state"
	mkdir "$state"
	echo "$fork" >"$state/fork"
	echo "$upstream" >"$state/upstream"
	echo "$base" >"$state/base"
	: >"$state/todo"
	: >"$state/applied"
	: >"$state/dropped"
	rename=""
	while read -r c; do
		if [ "$(git log -1 --format=%s "$c")" = "$RENAME_SUBJECT" ]; then
			rename=$c
		else
			echo "$c" >>"$state/todo"
		fi
	done < <(git rev-list --reverse --no-merges "$fork" "${exclude[@]}")
	if [ -z "$rename" ]; then
		rm -rf "$state"
		echo "sync-upstream: no \"$RENAME_SUBJECT\" commit in the stack" >&2
		exit 1
	fi

	git checkout -q -B "$BRANCH" "$upstream"
	git checkout -q "$rename" -- .fork/rename-module.sh
	.fork/rename-module.sh
	git add -A
	git commit -q -C "$rename"
fi

while [ -s "$state/todo" ]; do
	c=$(head -n 1 "$state/todo")
	tail -n +2 "$state/todo" >"$state/todo.next"
	mv "$state/todo.next" "$state/todo"
	echo "$c" >"$state/current"
	subject=$(git log -1 --format=%s "$c")
	before=$(git rev-parse HEAD)
	if ! git cherry-pick --empty=drop "$c" >/dev/null; then
		echo "sync-upstream: conflict applying ${c:0:12} \"$subject\"." >&2
		echo "Resolve it, stage the files, and run: .fork/sync-upstream.sh --continue" >&2
		exit 1
	fi
	if [ "$(git rev-parse HEAD)" = "$before" ]; then
		echo "$subject" >>"$state/dropped"
	else
		echo "$subject" >>"$state/applied"
	fi
done

fork=$(cat "$state/fork")
upstream=$(cat "$state/upstream")
base=$(cat "$state/base")
stack=$(git rev-parse HEAD)
gomod=$(git diff --unified=0 "$fork" "$stack" -- go.mod | grep '^[+-][^+-]' | tr -d '`' || true)
{
	echo "Sync with upstream ${upstream:0:12}"
	echo
	echo "Rebuilds the patch stack on refraction-networking/utls ${upstream:0:12}."
	echo
	echo "Upstream changes ($(git rev-list --count "$base..$upstream") commits):"
	echo "https://github.com/refraction-networking/utls/compare/$base...$upstream"
	echo
	if [ -n "$gomod" ]; then
		echo "go.mod changes, review new or bumped dependencies:"
		echo
		echo '```diff'
		echo "$gomod"
		echo '```'
	else
		echo "go.mod: unchanged."
	fi
	echo
	echo "Applied:"
	sed 's/^/- /' "$state/applied"
	if [ -s "$state/dropped" ]; then
		echo
		echo "Dropped, already upstream (update PATCHES.md):"
		sed 's/^/- /' "$state/dropped"
	fi
	echo
	echo "Upstream-Sync: $upstream"
} >"$state/message"

merge=$(git commit-tree "$stack^{tree}" -p "$fork" -p "$stack" -F "$state/message")
git reset -q --hard "$merge"
rm -rf "$state"
git log -1 --format=%B HEAD
