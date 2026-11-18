#!/usr/bin/env bash
set -uo pipefail

repo="SagerNet/sing-box-dashboard"
branch="gh-pages"

HP_DIR="${HP_DIR:-luci-app-homeproxy/root/etc/homeproxy}"
DASHBOARD_DIR="$HP_DIR/dashboard"
TMP_DIR="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
mkdir -p "$DASHBOARD_DIR"

err() { printf '%s\n' "$*" >&2; }
set_output() { [[ -z "${GITHUB_OUTPUT:-}" ]] || echo "changed=$1" >> "$GITHUB_OUTPUT"; }

commit_info="$(gh api "repos/$repo/commits?sha=$branch&per_page=1")" || { err "[DASHBOARD] failed to get latest version"; exit 1; }
commit_sha="$(jq -r '.[0].sha // empty' <<<"$commit_info")"
commit_date="$(jq -r '.[0].commit.committer.date // empty' <<<"$commit_info" | tr -cd '0-9')"
if [[ -z "$commit_sha" ]]; then
	err "[DASHBOARD] failed to get latest version"
	exit 1
fi

local_ver="$(sed -n '2p' "$DASHBOARD_DIR/dashboard.ver" 2>/dev/null || true)"
if [[ "$local_ver" == "$commit_sha" && -s "$DASHBOARD_DIR/index.html" ]]; then
	echo "[DASHBOARD] already up to date: $commit_sha"
	exit 0
fi
echo "[DASHBOARD] local: ${local_ver:-NOT FOUND}, latest: $commit_sha"

tmp_zip="$TMP_DIR/dashboard.zip"
tmp_dir="$TMP_DIR/dashboard-extract"
rm -rf "$tmp_zip" "$tmp_dir"
trap 'rm -rf "$tmp_zip" "$tmp_dir"' EXIT

if ! curl -fL --retry 3 "https://codeload.github.com/$repo/zip/$commit_sha" -o "$tmp_zip" || [[ ! -s "$tmp_zip" ]]; then
	err "[DASHBOARD] download failed"
	exit 1
fi

mkdir -p "$tmp_dir"
if ! unzip -q -o "$tmp_zip" -d "$tmp_dir"; then
	err "[DASHBOARD] extraction failed"
	exit 1
fi

index_file="$(find "$tmp_dir" -maxdepth 2 -name index.html | head -n1)"
if [[ -z "$index_file" ]]; then
	err "[DASHBOARD] invalid archive: index.html not found"
	exit 1
fi

if ! rsync -a --delete --exclude='dashboard.ver' "$(dirname "$index_file")"/ "$DASHBOARD_DIR"/; then
	err "[DASHBOARD] sync failed"
	exit 1
fi

printf '%s\n%s\n' "$commit_date" "$commit_sha" > "$DASHBOARD_DIR/dashboard.ver"
echo "[DASHBOARD] updated successfully"
set_output true
