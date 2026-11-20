#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022-2025 ImmortalWrt.org

NAME="homeproxy"

RESOURCES_DIR="/etc/$NAME/resources"
DASHBOARD_DIR="/etc/$NAME/dashboard"
mkdir -p "$RESOURCES_DIR" "$DASHBOARD_DIR"

RUN_DIR="/var/run/$NAME"
LOG_PATH="$RUN_DIR/$NAME.log"
mkdir -p "$RUN_DIR"

log() {
	echo -e "$(date "+%Y-%m-%d %H:%M:%S") $*" >> "$LOG_PATH"
}

to_upper() {
	echo -e "$1" | tr "[a-z]" "[A-Z]"
}

check_list_update() {
	local listtype="$1"
	local listrepo="$2"
	local listref="$3"
	local listname="$4"
	local lock="$RUN_DIR/update_resources-$listtype.lock"
	local github_token="$(uci -q get homeproxy.config.github_token)"
	local wget="wget --timeout=10 -q"

	exec 200>"$lock"
	if ! flock -n 200 &> "/dev/null"; then
		log "[$(to_upper "$listtype")] A task is already running."
		return 2
	fi

	[ -z "$github_token" ] || github_token="--header=Authorization: Bearer $github_token"
	local list_info="$($wget "${github_token:--q}" -O- "https://api.github.com/repos/$listrepo/commits?sha=$listref&path=$listname&per_page=1")"
	local list_sha="$(echo -e "$list_info" | jsonfilter -qe "@[0].sha")"
	local list_ver="$(echo -e "$list_info" | jsonfilter -qe "@[0].commit.message" | grep -Eo "[0-9-]+" | tr -d '-')"
	if [ -z "$list_sha" ] || [ -z "$list_ver" ]; then
		log "[$(to_upper "$listtype")] Failed to get the latest version, please retry later."
		return 1
	fi

	local local_list_ver="$(cat "$RESOURCES_DIR/$listtype.ver" 2>"/dev/null" || echo "NOT FOUND")"
	if [ "$local_list_ver" = "$list_ver" ]; then
		log "[$(to_upper "$listtype")] Current version: $list_ver."
		log "[$(to_upper "$listtype")] You're already at the latest version."
		return 3
	else
		log "[$(to_upper "$listtype")] Local version: $local_list_ver, latest version: $list_ver."
	fi

	if ! $wget "https://fastly.jsdelivr.net/gh/$listrepo@$list_sha/$listname" -O "$RUN_DIR/$listname" || [ ! -s "$RUN_DIR/$listname" ]; then
		rm -f "$RUN_DIR/$listname"
		log "[$(to_upper "$listtype")] Update failed."
		return 1
	fi

	mv -f "$RUN_DIR/$listname" "$RESOURCES_DIR/$listtype.${listname##*.}"
	echo -e "$list_ver" > "$RESOURCES_DIR/$listtype.ver"
	log "[$(to_upper "$listtype")] Successfully updated."

	return 0
}

check_dashboard_update() {
	local repo="SagerNet/sing-box-dashboard"
	local branch="gh-pages"
	local lock="$RUN_DIR/update_resources-dashboard.lock"
	local github_token="$(uci -q get homeproxy.config.github_token)"
	local wget="wget --timeout=10 -q"

	exec 201>"$lock"
	if ! flock -n 201 &> "/dev/null"; then
		log "[DASHBOARD] A task is already running."
		return 2
	fi

	[ -z "$github_token" ] || github_token="--header=Authorization: Bearer $github_token"
	local commit_info="$($wget "${github_token:--q}" -O- "https://api.github.com/repos/$repo/commits?sha=$branch&per_page=1")"
	local commit_sha="$(echo -e "$commit_info" | jsonfilter -qe "@[0].sha")"
	local commit_date="$(echo -e "$commit_info" | jsonfilter -qe "@[0].commit.committer.date" 2>"/dev/null" | tr -cd "0-9")"
	if [ -z "$commit_sha" ]; then
		log "[DASHBOARD] Failed to get the latest version, please retry later."
		return 1
	fi

	local local_ver="$(sed -n "2p" "$DASHBOARD_DIR/dashboard.ver" 2>"/dev/null")"
	if [ "$local_ver" = "$commit_sha" ] && [ -s "$DASHBOARD_DIR/index.html" ]; then
		log "[DASHBOARD] Current version: $commit_sha."
		log "[DASHBOARD] You're already at the latest version."
		return 3
	else
		log "[DASHBOARD] Local version: $local_ver, latest version: $commit_sha."
	fi

	local tmp_zip="$RUN_DIR/dashboard.zip"
	local tmp_dir="$RUN_DIR/dashboard-extract"
	local staging="$DASHBOARD_DIR.new.$$"
	rm -rf "$tmp_zip" "$tmp_dir" "$staging"

	if ! $wget "${github_token:--q}" -O "$tmp_zip" "https://codeload.github.com/$repo/zip/$commit_sha" || [ ! -s "$tmp_zip" ]; then
		rm -rf "$tmp_zip" "$tmp_dir"
		log "[DASHBOARD] Update failed while downloading the dashboard."
		return 1
	fi

	mkdir -p "$tmp_dir"
	if ! unzip -q -o "$tmp_zip" -d "$tmp_dir" &> "/dev/null"; then
		rm -rf "$tmp_zip" "$tmp_dir"
		log "[DASHBOARD] Update failed while extracting the dashboard."
		return 1
	fi

	local index_file="$(find "$tmp_dir" -maxdepth 2 -name "index.html" | head -n1)"
	if [ -z "$index_file" ] || ! cp -a "${index_file%/index.html}" "$staging"; then
		rm -rf "$tmp_zip" "$tmp_dir" "$staging"
		log "[DASHBOARD] Update failed: invalid dashboard archive."
		return 1
	fi

	chmod 755 "$staging"
	find "$staging" -type d -exec chmod 755 {} +
	find "$staging" -type f -exec chmod 644 {} +

	if ! cp -a "$staging"/. "$DASHBOARD_DIR"/; then
		rm -rf "$tmp_zip" "$tmp_dir" "$staging"
		log "[DASHBOARD] Update failed while installing the dashboard."
		return 1
	fi

	local old_list="$RUN_DIR/dashboard-files.old"
	local new_list="$RUN_DIR/dashboard-files.new"
	(cd "$DASHBOARD_DIR" && find . -type f) | sort > "$old_list"
	(cd "$staging" && find . -type f) | sort > "$new_list"
	comm -23 "$old_list" "$new_list" | while read -r f; do
		case "$f" in
		"./dashboard.ver")
			;;
		*)
			rm -f "$DASHBOARD_DIR/${f#./}"
			;;
		esac
	done
	rm -f "$old_list" "$new_list"

	rm -rf "$tmp_zip" "$tmp_dir" "$staging"
	printf "%s\n%s\n" "$commit_date" "$commit_sha" > "$DASHBOARD_DIR/dashboard.ver"
	log "[DASHBOARD] Successfully updated."

	return 0
}

case "$1" in
"china_ip4")
	check_list_update "$1" "1715173329/IPCIDR-CHINA" "master" "ipv4.txt"
	;;
"china_ip6")
	check_list_update "$1" "1715173329/IPCIDR-CHINA" "master" "ipv6.txt"
	;;
"dashboard")
	check_dashboard_update
	;;
*)
	echo -e "Usage: $0 <china_ip4 / china_ip6 / dashboard>"
	exit 1
	;;
esac
