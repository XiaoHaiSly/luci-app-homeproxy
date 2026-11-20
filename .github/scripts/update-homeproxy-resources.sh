#!/usr/bin/env bash
set -uo pipefail

HP_DIR="${HP_DIR:-luci-app-homeproxy/root/etc/homeproxy}"
RESOURCES_DIR="$HP_DIR/resources"
TMP_DIR="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
mkdir -p "$RESOURCES_DIR"

updated=()
failed=()

log() { printf '%s\n' "$*"; }
err() { printf '%s\n' "$*" >&2; }

check_list_update() {
	local listtype="$1"
	local listrepo="$2"
	local listref="$3"
	local listname="$4"
	local info sha ver local_ver tmp

	info="$(gh api "repos/$listrepo/commits?sha=$listref&path=$listname&per_page=1")" || return 1
	sha="$(jq -r '.[0].sha // empty' <<<"$info")"
	ver="$(jq -r '.[0].commit.message // empty' <<<"$info" | head -n1 \
		| grep -Eo '[0-9-]+' | tr -d '\n-' || true)"
	[[ -n "$ver" ]] || ver="$(jq -r '.[0].commit.committer.date // empty' <<<"$info" | tr -cd '0-9')"
	if [[ -z "$sha" || -z "$ver" ]]; then
		err "[$listtype] failed to get latest version"
		return 1
	fi

	local_ver="$(cat "$RESOURCES_DIR/$listtype.ver" 2>/dev/null || echo "NOT FOUND")"
	if [[ "$local_ver" == "$ver" && -s "$RESOURCES_DIR/$listtype.${listname##*.}" ]]; then
		log "[$listtype] already up to date: $ver"
		return 0
	fi
	log "[$listtype] local: $local_ver, latest: $ver"

	tmp="$TMP_DIR/$listname"
	if ! curl -fL --retry 3 "https://raw.githubusercontent.com/$listrepo/$sha/$listname" -o "$tmp" || [[ ! -s "$tmp" ]]; then
		rm -f "$tmp"
		err "[$listtype] download failed"
		return 1
	fi

	mv -f "$tmp" "$RESOURCES_DIR/$listtype.${listname##*.}" || return 1
	printf '%s\n' "$ver" > "$RESOURCES_DIR/$listtype.ver" || return 1
	log "[$listtype] updated successfully"
	updated+=("$listtype")
}

[[ $# -gt 0 ]] || { err "Usage: $0 <china_ip4 / china_ip6> [...]"; exit 1; }

for target in "$@"; do
	case "$target" in
	"china_ip4")
		check_list_update "$target" "1715173329/IPCIDR-CHINA" "master" "ipv4.txt"
		;;
	"china_ip6")
		check_list_update "$target" "1715173329/IPCIDR-CHINA" "master" "ipv6.txt"
		;;
	*)
		err "Usage: $0 <china_ip4 / china_ip6> [...]"
		false
		;;
	esac || failed+=("$target")
done

[[ -z "${GITHUB_OUTPUT:-}" ]] || echo "updated=${updated[*]:-}" >> "$GITHUB_OUTPUT"

if (( ${#failed[@]} )); then
	err "Failed: ${failed[*]}"
	exit 1
fi
