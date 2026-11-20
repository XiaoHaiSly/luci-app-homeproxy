#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2025 ImmortalWrt.org
 *
 * Migrates a configuration created before the sing-box 1.14 rework to the
 * current layout:
 *
 *   - the custom, gfwlist and "only proxy mainland China" routing modes are gone,
 *     together with its rule, DNS and rule set editors
 *   - one node (or URLTest group) carries both TCP and UDP now
 *   - DNS fallback servers, the dashboard and the TUN stack option are new
 *   - the Tailscale endpoint was introduced
 */

'use strict';

import { cursor } from 'uci';
import { isEmpty } from 'homeproxy';

const uci = cursor();

const uciconfig = 'homeproxy';
uci.load(uciconfig);

const ucimain = 'config';

/* the custom routing modes were removed */
if (uci.get(uciconfig, ucimain, 'routing_mode') in ['custom', 'gfwlist', 'proxy_mainland_china'])
	uci.set(uciconfig, ucimain, 'routing_mode', 'bypass_mainland_china');

/* the China IP bypass and the QUIC reject became switches, keep the old behavior */
for (let option in [ 'bypass_china_ip', 'reject_quic' ])
	if (uci.get(uciconfig, ucimain, option) === null)
		uci.set(uciconfig, ucimain, option, '1');

/* the TUN stack option was removed, sing-box always uses its own stack now */
if (uci.get(uciconfig, ucimain, 'tcpip_stack') !== null)
	uci.delete(uciconfig, ucimain, 'tcpip_stack');

/* the IPv6 fallback is now part of the IPv6 support switch */
if (uci.get(uciconfig, ucimain, 'ipv6_fallback') !== null)
	uci.delete(uciconfig, ucimain, 'ipv6_fallback');

/* the common port preset was extended, migrate the old default in place */
const legacy_common_port = '22,53,80,143,443,465,587,853,873,993,995,5222,8080,8443,9418';
const common_port = uci.get(uciconfig, 'infra', 'common_port');

if (isEmpty(common_port) || common_port === legacy_common_port)
	uci.set(uciconfig, 'infra', 'common_port',
		'20,21,22,25,53,80,110,119,123,143,389,443,465,514,563,587,636,853,873,989,990,993,995,1194,1883,3306,3389,5222,5432,5671,5672,5900,6379,6443,6514,8080,8443,8883,9418');

/* the separate UDP node was removed, one node carries TCP and UDP */
for (let option in [ 'main_udp_node', 'main_udp_urltest_nodes',
                     'main_udp_urltest_interval', 'main_udp_urltest_tolerance' ])
	if (uci.get(uciconfig, ucimain, option) !== null)
		uci.delete(uciconfig, ucimain, option);

/* the DNS servers are a single group now, the separate fallback lists are gone */
for (let option in [ 'dns_server_fallback', 'china_dns_server_fallback' ])
	if (uci.get(uciconfig, ucimain, option) !== null)
		uci.delete(uciconfig, ucimain, option);

if (isEmpty(uci.get(uciconfig, ucimain, 'dns_fallback_strategy')))
	uci.set(uciconfig, ucimain, 'dns_fallback_strategy', 'sequential');

/* the dashboard was introduced */
if (isEmpty(uci.get(uciconfig, ucimain, 'dashboard_port')))
	uci.set(uciconfig, ucimain, 'dashboard_port', '9096');
if (uci.get(uciconfig, ucimain, 'dashboard_secret') === null)
	uci.set(uciconfig, ucimain, 'dashboard_secret', '');

/* the Tailscale endpoint was introduced */
if (isEmpty(uci.get(uciconfig, 'tailscale')))
	uci.set(uciconfig, 'tailscale', 'homeproxy');

for (let option in [ 'enabled', 'accept_routes', 'exit_node_allow_lan_access', 'advertise_exit_node' ])
	if (uci.get(uciconfig, 'tailscale', option) === null)
		uci.set(uciconfig, 'tailscale', option, '0');

/* drop the leftovers of the removed custom routing mode */
for (let section in [ 'routing', 'dns' ])
	if (uci.get(uciconfig, section) === 'homeproxy')
		uci.delete(uciconfig, section);

/* collect first, deleting while iterating is not reliable */
for (let stype in [ 'routing_node', 'routing_rule', 'dns_server', 'dns_rule', 'ruleset' ]) {
	let sections = [];

	uci.foreach(uciconfig, stype, (cfg) => push(sections, cfg['.name']));

	for (let name in sections)
		uci.delete(uciconfig, name);
}

if (!isEmpty(uci.changes(uciconfig)))
	uci.commit(uciconfig);
