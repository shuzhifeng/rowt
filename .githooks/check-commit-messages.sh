#!/bin/sh
# Refuse agent-attribution lines in commit messages and PR descriptions (Hong's ruling,
# 2026-10-05: no Co-Authored-By: Claude, Claude-Session or "Generated with Claude Code", in
# any repo). Adapted from knack's scripts/check-commit-messages.sh.
#
#   check-commit-messages.sh <base>..<head>    the commits in the range (CI, push and PR)
#   check-commit-messages.sh --message <file>  one message about to be committed (.githooks/commit-msg),
#                                              or a PR description CI wrote to a file
#
# Exits 0 when nothing matches, 1 naming each offending line, 2 on a bad range or usage.
# Commits already on main keep their lines: the gate reads only the range it is given.
set -eu
export LC_ALL=C

# Matched case-insensitively: a trailer naming Claude as co-author, a session trailer, the
# generated-with line, the vendor's address. Unlike knack, NOT the vendor's bare name: rowt's
# escape lane lists the vendor's domains, and a commit that edits that list names them.
attribution() {
    grep -n -i -E \
        -e '^[[:space:]]*co-authored-by[[:space:]]*:.*claude' \
        -e '^[[:space:]]*claude-session[[:space:]]*:' \
        -e 'generated with[[:space:]]+\[?claude code' \
        -e 'noreply@anthropic\.com' || [ $? -eq 1 ] || exit 2
}

usage() {
    echo 'usage: check-commit-messages.sh <base>..<head> | --message <file>' >&2
    exit 2
}

refuse() {
    echo "check-commit-messages: $1; remove the lines named above (no agent attribution, ruling of 2026-10-05)" >&2
    exit 1
}

if [ "${1:-}" = --message ]; then
    [ $# -eq 2 ] && [ -f "$2" ] || usage
    # What git will commit: no comments, nothing below `git commit -v`'s scissors line.
    found=$(sed '/ -\{24\} >8 -\{24\}$/,$d' "$2" | git stripspace --strip-comments | attribution)
    [ -n "$found" ] || exit 0
    printf '%s\n' "$found" | sed 's/^/    /' >&2
    refuse 'this message carries lines the ruling refuses'
fi

[ $# -eq 1 ] || usage
case $1 in
    ..*|*..|*...*) usage ;;
    *..*) ;;
    *) usage ;;
esac
base=${1%%..*}
head=${1#*..}
for rev in "$base" "$head"; do
    git rev-parse --quiet --verify "$rev^{commit}" >/dev/null ||
        { echo "check-commit-messages: not a commit: $rev" >&2; exit 2; }
done
commits=$(git rev-list "$base..$head") ||
    { echo "check-commit-messages: cannot list $1" >&2; exit 2; }

offenders=0
for commit in $commits; do
    found=$(git log -1 --format=%B "$commit" | attribution)
    [ -n "$found" ] || continue
    offenders=$((offenders + 1))
    git log -1 --format='%h %s' "$commit" >&2
    printf '%s\n' "$found" | sed 's/^/    /' >&2
done
[ "$offenders" -eq 0 ] || refuse "$offenders commit(s) in $1 carry lines the ruling refuses"
