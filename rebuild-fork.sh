#!/bin/sh
# Rebuild the fork's integration branch: origin/main (a pure mirror of upstream/main) plus every
# topic branch, merged in order. Topics branch from main, so each can go upstream as a PR, except
# the fork-only topic/stream-strip, which builds on a fork build and is merged after the fix topics
# (its copies of them are the same changes, so they merge cleanly), and topic/inspect-security-handler,
# which builds on stream-strip.
#
# This script lives on the fork's orphan `fork-tools` branch, apart from the code. Run it from a
# worktree made for it, with a clean tree, never from the shared checkout:
#   git worktree add O:/Projects/Worktrees/lopdf-fork-rebuild fork
#   git show origin/fork-tools:rebuild-fork.sh > "$(git rev-parse --git-common-dir)/rebuild-fork.sh"
#   sh "$(git rev-parse --git-common-dir)/rebuild-fork.sh"
#
# Before a run after an upstream sync: fast-forward origin's main to upstream/main, merge main into
# each fix topic and push it, then merge an interim build of the fix topics into topic/stream-strip,
# and stream-strip into topic/inspect-security-handler, and push those.
#
# Edit TOPICS when a topic is added, or retired after upstream takes it. Retired so far, because
# upstream took them: real-precision (#674), real-point (#649), encrypt-length (#647),
# xref-free-entries (#648) and stream-dict-strings (#603/#608).
set -e

TOPICS="topic/secret-hygiene topic/unpack-limits topic/crypt-filter-defaults topic/decrypt-errors topic/embedded-file-filter topic/encrypted-object-streams topic/xref-entries topic/stream-strip topic/inspect-security-handler"
TRAILER="Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
JOBS="${JOBS:-10}"
TEST_THREADS="${TEST_THREADS:-8}"

test -z "$(git status --porcelain)" || { echo "working tree not clean" >&2; exit 1; }
git fetch -q upstream
git fetch -q origin

# The shared checkout keeps the local main checked out, so build from origin/main, which must be
# upstream/main exactly.
if [ "$(git rev-parse origin/main)" != "$(git rev-parse upstream/main)" ]; then
    echo "origin/main is not upstream/main: push upstream/main to origin's main first" >&2
    exit 1
fi

# Topics are built from origin, where their pull requests merge. A local copy with commits origin
# lacks has unpushed work: push it, or drop it, first.
for t in $TOPICS; do
    git rev-parse -q --verify "refs/remotes/origin/$t" >/dev/null || { echo "origin has no $t" >&2; exit 1; }
    if git rev-parse -q --verify "refs/heads/$t" >/dev/null &&
        [ -n "$(git rev-list "origin/$t..$t")" ]; then
        echo "$t has commits origin/$t lacks: push them first" >&2
        exit 1
    fi
done

old_fork="$(git rev-parse origin/fork)"
git checkout -q -B fork origin/main
for t in $TOPICS; do
    if ! git merge -q --no-ff -m "Merge $t into fork" -m "$TRAILER" "origin/$t"; then
        # rerere (with rerere.autoUpdate) replays and stages a resolution recorded on an earlier
        # rebuild; only a conflict it has not seen stops the script. Resolve it, commit, and re-run:
        # the commit records the resolution for the next run.
        if [ -n "$(git diff --name-only --diff-filter=U)" ] || git grep -q -E '^(<<<<<<<|>>>>>>>) ' -- .; then
            echo "conflict merging $t: resolve and commit it, then re-run this script" >&2
            exit 1
        fi
        git commit -q --no-edit
    fi
done

# Only the topics' own files: upstream's are upstream's to format.
changed_rs="$(git diff --name-only origin/main HEAD -- '*.rs')"
if [ -n "$changed_rs" ]; then
    # shellcheck disable=SC2086
    rustfmt --check --edition 2024 $changed_rs
fi
cargo clippy -q -j "$JOBS" --workspace --all-targets -- -D warnings
cargo clippy -q -j "$JOBS" --workspace --all-targets --all-features -- -D warnings
# The default features run the not(feature = "async") tests that --all-features skips.
cargo test -q -j "$JOBS" -- --test-threads="$TEST_THREADS"
cargo test -q -j "$JOBS" --all-features -- --test-threads="$TEST_THREADS"

tag="fork-$(date +%Y%m%d-%H%M)"
git tag "$tag"
echo "built fork at $(git rev-parse HEAD), tagged $tag"
echo "push with: git push --force-with-lease=fork:$old_fork origin fork && git push origin $tag"
