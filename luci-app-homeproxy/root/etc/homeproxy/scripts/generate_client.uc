#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2023-2025 ImmortalWrt.org
 */

'use strict';

import { readfile, writefile } from 'fs';
import { isnan } from 'math';
import { connect } from 'ubus';
import { cursor } from 'uci';

import {
	isEmpty, normalizeList, parseURL, parseHeaderList, rangeValue, strToBool, strToInt, strToTime,
	removeBlankAttrs, validation, xhttpPadding, strToDuration, HP_DIR, RUN_DIR
} from 'homeproxy';

const ubus = connect();

/* const features = ubus.call('luci.homeproxy', 'singbox_get_features') || {}; */

/* UCI config start */
const uci = cursor();

const uciconfig = 'homeproxy';
uci.load(uciconfig);

const uciinfra = 'infra',
      ucimain = 'config',
      ucicontrol = 'control',
      ucitalscale = 'tailscale';

const ucinode = 'node';
const uciapprule = 'app_rule';

/* Rule sets used by the application based routing rules */
const app_rule_urls = {
	youtube: {
		domain: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/youtube.srs'
	},
	tiktok: {
		domain: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/tiktok.srs'
	},
	telegram: {
		domain: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/telegram.srs',
		ip: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/telegram.srs'
	},
	twitter: {
		domain: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/twitter.srs',
		ip: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/twitter.srs'
	},
	google: {
		domain: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/google.srs',
		ip: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/google.srs'
	},
	cloudflare: {
		domain: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/cloudflare.srs',
		ip: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cloudflare.srs'
	},
	github: {
		domain: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/github.srs'
	},
	ai_noncn: {
		domain: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-ai-!cn.srs'
	}
};

let routing_mode = uci.get(uciconfig, ucimain, 'routing_mode') || 'bypass_mainland_china';
/* custom, gfwlist and proxy_mainland_china were removed, migrate_config.uc rewrites them */
if (routing_mode in ['custom', 'gfwlist', 'proxy_mainland_china'])
	routing_mode = 'bypass_mainland_china';

/*
 * When on, the firewall returns mainland China IPs before the core sees them.
 * When off, all traffic enters the core, which sends the China domains and
 * China IPs (geosite-cn / geoip-cn) direct on its own.
 */
const bypass_china_ip = (routing_mode === 'bypass_mainland_china') &&
	(uci.get(uciconfig, ucimain, 'bypass_china_ip') !== '0');

let wan_dns = ubus.call('network.interface', 'status', {'interface': 'wan'})?.['dns-server']?.[0];
if (!wan_dns)
	wan_dns = (routing_mode === 'global') ? '8.8.8.8' : '223.5.5.5';

const dns_port = uci.get(uciconfig, uciinfra, 'dns_port') || '5333';

const dns_server_fallback = normalizeList(uci.get(uciconfig, ucimain, 'dns_server_fallback')),
      china_dns_server_fallback = normalizeList(uci.get(uciconfig, ucimain, 'china_dns_server_fallback')),
      dns_fallback_strategy = uci.get(uciconfig, ucimain, 'dns_fallback_strategy') || 'sequential';

const ntp_server = uci.get(uciconfig, uciinfra, 'ntp_server') || 'time.apple.com';

const ipv6_support = uci.get(uciconfig, ucimain, 'ipv6_support') || '0';

let main_node, dns_server, china_dns_server,
    dns_default_strategy, direct_domain_list, proxy_domain_list;

main_node = uci.get(uciconfig, ucimain, 'main_node') || 'nil';

/* a stale reference (deleted node) must not break the configuration */
if (!isEmpty(main_node) && main_node !== 'urltest' && main_node !== 'fallback' &&
    main_node !== 'balancer' && type(uci.get_all(uciconfig, main_node)) !== 'object')
	main_node = 'nil';

const main_urltest_nodes = normalizeList(uci.get(uciconfig, ucimain, 'main_urltest_nodes'));

/* a group without members cannot be generated */
if (main_node === 'urltest' && !length(main_urltest_nodes))
	main_node = 'nil';

const main_fallback_nodes = normalizeList(uci.get(uciconfig, ucimain, 'main_fallback_nodes'));

if (main_node === 'fallback' && !length(main_fallback_nodes))
	main_node = 'nil';

const main_balancer_nodes = normalizeList(uci.get(uciconfig, ucimain, 'main_balancer_nodes'));

if (main_node === 'balancer' && !length(main_balancer_nodes))
	main_node = 'nil';

dns_server = uci.get(uciconfig, ucimain, 'dns_server');
if (isEmpty(dns_server) || dns_server === 'wan')
	dns_server = wan_dns;

if (routing_mode === 'bypass_mainland_china') {
	china_dns_server = uci.get(uciconfig, ucimain, 'china_dns_server');
	if (isEmpty(china_dns_server) || type(china_dns_server) !== 'string' || china_dns_server === 'wan')
		china_dns_server = wan_dns;
}
dns_default_strategy = (ipv6_support !== '1') ? 'ipv4_only' : null;

direct_domain_list = trim(readfile(HP_DIR + '/resources/direct_list.txt'));
if (direct_domain_list)
	direct_domain_list = split(direct_domain_list, /[\r\n]/);

proxy_domain_list = trim(readfile(HP_DIR + '/resources/proxy_list.txt'));
if (proxy_domain_list)
	proxy_domain_list = split(proxy_domain_list, /[\r\n]/);
const proxy_mode = uci.get(uciconfig, ucimain, 'proxy_mode') || 'redirect_tproxy',
      default_interface = uci.get(uciconfig, ucicontrol, 'bind_interface');

const mixed_port = uci.get(uciconfig, uciinfra, 'mixed_port') || '5330';

let self_mark, redirect_port, tproxy_port, tun_name,
    tun_addr4, tun_addr6, tun_mtu, udp_timeout;

udp_timeout = uci.get(uciconfig, uciinfra, 'udp_timeout');

/*
 * Every mode needs the mark: the sockets sing-box creates for its own
 * outbounds (proxy nodes, direct, endpoints) carry it, so the redirect and
 * TUN rules never capture the traffic a second time. Without it a pure TUN
 * setup loops its own connections back into the tun.
 */
self_mark = uci.get(uciconfig, 'infra', 'self_mark') || '100';

if (match(proxy_mode, /redirect/))
	redirect_port = uci.get(uciconfig, 'infra', 'redirect_port') || '5331';
if (match(proxy_mode, /tproxy/))
	tproxy_port = uci.get(uciconfig, 'infra', 'tproxy_port') || '5332';
if (match(proxy_mode, /tun/)) {
	tun_name = uci.get(uciconfig, uciinfra, 'tun_name') || 'singtun0';
	tun_addr4 = uci.get(uciconfig, uciinfra, 'tun_addr4') || '172.19.0.1/30';
	tun_addr6 = uci.get(uciconfig, uciinfra, 'tun_addr6') || 'fdfe:dcba:9876::1/126';
	tun_mtu = uci.get(uciconfig, uciinfra, 'tun_mtu') || '9000';
}

const log_level = uci.get(uciconfig, ucimain, 'log_level') || 'warn';

/* The bundled sing-box dashboard is served by the core itself */
const dashboard_path = HP_DIR + '/dashboard';
const dashboard_enabled = !isEmpty(readfile(dashboard_path + '/index.html')),
      dashboard_port = strToInt(uci.get(uciconfig, ucimain, 'dashboard_port')) || 9096,
      dashboard_secret = uci.get(uciconfig, ucimain, 'dashboard_secret');

/*
 * Tailscale endpoint (sing-box >= 1.14). The endpoint works on its own, a main
 * node is not required: the router simply joins the tailnet and the traffic of
 * the tailnet peers is left untouched by the proxy.
 */
const tailscale_tag = 'tailscale-out';
const tailscale_enabled = uci.get(uciconfig, ucitalscale, 'enabled') === '1';
const tailscale_auth_key = uci.get(uciconfig, ucitalscale, 'auth_key');
const tailscale_control_url = uci.get(uciconfig, ucitalscale, 'control_url');
const tailscale_hostname = uci.get(uciconfig, ucitalscale, 'hostname');
const tailscale_accept_routes = uci.get(uciconfig, ucitalscale, 'accept_routes') === '1';
const tailscale_exit_node = uci.get(uciconfig, ucitalscale, 'exit_node');
const tailscale_exit_node_allow_lan_access =
	uci.get(uciconfig, ucitalscale, 'exit_node_allow_lan_access') === '1';
const tailscale_advertise_routes = normalizeList(uci.get(uciconfig, ucitalscale, 'advertise_routes'));
const tailscale_listen_port = uci.get(uciconfig, ucitalscale, 'listen_port');

let tailscale_advertise_exit_node = uci.get(uciconfig, ucitalscale, 'advertise_exit_node') === '1';

/* A node cannot use an exit node and advertise itself as one at the same time,
   keep the service running and drop the advertisement instead of failing. */
if (tailscale_enabled && !isEmpty(tailscale_exit_node) && tailscale_advertise_exit_node) {
	warn('Tailscale: an exit node cannot be used and advertised at the same time, disabling the advertisement.\n');
	tailscale_advertise_exit_node = false;
}
/* UCI config end */

/*
 * Outbound tags are derived from the node labels (with a numeric suffix when
 * labels collide) so the dashboard and the API show readable node names
 * instead of internal section ids.
 */
const reserved_out_tags = {
	'direct-out': true,
	'block-out': true,
	'main-out': true,
	'tailscale-out': true
};
const node_out_tags = {};

uci.foreach(uciconfig, ucinode, (cfg) => {
	const base = trim(cfg.label || '') || cfg['.name'];
	let tag = base, suffix = 2;

	while (reserved_out_tags[tag])
		tag = `${base} (${suffix++})`;

	reserved_out_tags[tag] = true;
	node_out_tags[cfg['.name']] = tag;
});

function node_out_tag(id) {
	return node_out_tags[id] || ('cfg-' + id + '-out');
}

/*
 * The main outbound keeps the well-known tag for the groups, a single main
 * node is referenced by its label based tag.
 */
let main_out_tag = (isEmpty(main_node) || main_node === 'urltest' || main_node === 'fallback' ||
	main_node === 'balancer') ? 'main-out' : node_out_tag(main_node);

/* Config helper start */
/*
 * A positive number that may hold a fraction. Empty or invalid is dropped so
 * that the default of the core applies instead of an invalid value.
 */
function strToFloat(str) {
	if (isEmpty(str))
		return null;

	const val = +str;

	return (isnan(val) || val <= 0) ? null : val;
}

function parse_port(strport) {
	if (type(strport) !== 'array' || isEmpty(strport))
		return null;

	let ports = [];
	for (let i in strport)
		push(ports, int(i));

	return ports;

}

function parse_dnsserver(server_addr, default_protocol) {
	if (isEmpty(server_addr))
		return null;

	if (!match(server_addr, /:\/\//))
		server_addr = (default_protocol || 'udp') + '://' + (validation('ip6addr', server_addr) ? `[${server_addr}]` : server_addr);
	server_addr = parseURL(server_addr);

	return {
		type: server_addr.protocol,
		server: server_addr.hostname,
		server_port: strToInt(server_addr.port),
		path: (server_addr.pathname !== '/') ? server_addr.pathname : null,
	}
}


/*
 * The core rejects max_connections together with max_concurrency; keep the
 * range based one (the more expressive of the two) and drop the other.
 */
function normalize_xmux(xmux) {
	if (!xmux)
		return null;

	if (!isEmpty(xmux.max_concurrency) && !isEmpty(xmux.max_connections))
		xmux.max_connections = null;

	return xmux;
}

function generate_endpoint(node) {
	if (type(node) !== 'object' || isEmpty(node))
		return null;

	const endpoint = {
		type: node.type,
		tag: node_out_tag(node['.name']),
		address: node.wireguard_local_address,
		mtu: strToInt(node.wireguard_mtu),
		private_key: node.wireguard_private_key,
		peers: (node.type === 'wireguard') ? [
			{
				address: node.address,
				port: strToInt(node.port),
				allowed_ips: [
					'0.0.0.0/0',
					'::/0'
				],
				persistent_keepalive_interval: strToInt(node.wireguard_persistent_keepalive_interval),
				public_key: node.wireguard_peer_public_key,
				pre_shared_key: node.wireguard_pre_shared_key,
				reserved: parse_port(node.wireguard_reserved),
			}
		] : null,
		system: (node.type === 'wireguard') ? false : null,
		tcp_fast_open: strToBool(node.tcp_fast_open),
		tcp_multi_path: strToBool(node.tcp_multi_path),
		udp_fragment: strToBool(node.udp_fragment)
	};

	return endpoint;
}

/*
 * The core rejects a "Host" entry inside the XHTTP header list (the host is a
 * dedicated option), and the header/cookie uplink data placements as well as
 * the GET uplink method are only valid in packet-up mode.
 */
function xhttp_headers(list) {
	const headers = parseHeaderList(list);
	if (!headers)
		return null;

	for (let name in headers)
		if (match(name, /^host$/i)) {
			warn(`homeproxy: the "Host" header belongs to the XHTTP host field, dropping it from the header list.\n`);
			delete headers[name];
		}

	return isEmpty(headers) ? null : headers;
}

function xhttp_uplink_data_placement(value, packet_up) {
	if (isEmpty(value))
		return null;

	if (!packet_up && (value === 'header' || value === 'cookie')) {
		warn(`homeproxy: uplink data placement "${value}" requires the packet-up mode, ignoring it.\n`);
		return null;
	}

	return value;
}

function xhttp_uplink_method(value, packet_up) {
	if (isEmpty(value))
		return null;

	if (!packet_up && match(value, /^get$/i)) {
		warn('homeproxy: the GET uplink method requires the packet-up mode, ignoring it.\n');
		return null;
	}

	return value;
}

function generate_outbound(node) {
	if (type(node) !== 'object' || isEmpty(node))
		return null;

	const is_hysteria1 = (node.type === 'hysteria'),
	      is_hysteria2 = (node.type === 'hysteria2');

	/* hysteria v1 refuses to start without a declared bandwidth */
	const hysteria1_up = strToInt(node.hysteria_up_mbps),
	      hysteria1_down = strToInt(node.hysteria_down_mbps);

	if (is_hysteria1 && (!hysteria1_up || !hysteria1_down))
		warn('homeproxy: hysteria requires the upload and download speed, falling back to 100 Mbps.\n');

	/* The realm takes over the server discovery, so the static address is dropped */
	let hysteria_realm = is_hysteria2 && (node.hysteria2_realm === '1');

	if (hysteria_realm && (isEmpty(node.hysteria2_realm_server_url) ||
	    isEmpty(node.hysteria2_realm_id) || isEmpty(normalizeList(node.hysteria2_realm_stun_servers)))) {
		warn('homeproxy: the hysteria2 realm needs a server URL, a realm ID and at least one STUN server, ignoring it.\n');
		hysteria_realm = false;
	}

	const tls_reality_on = (node.tls === '1' && node.tls_reality === '1'),
	      tls_spoof_host = (node.tls === '1' && !tls_reality_on && !isEmpty(node.tls_spoof)) ?
		node.tls_spoof : null;

	if (node.tls === '1' && isEmpty(node.tls_spoof) && !isEmpty(node.tls_spoof_method))
		warn('homeproxy: the TLS spoof method requires a spoof host, ignoring it.\n');
	if (tls_reality_on && !isEmpty(node.tls_spoof))
		warn('homeproxy: TLS spoof is not supported together with REALITY, ignoring it.\n');
	if (tls_reality_on && isEmpty(node.tls_utls))
		warn('homeproxy: REALITY requires uTLS, falling back to the chrome fingerprint.\n');

	const is_xhttp = (node.transport === 'xhttp'),
	      xhttp_packet_up = is_xhttp && (node.xhttp_mode === 'packet-up');

	const outbound = {
		type: node.type,
		tag: node_out_tag(node['.name']),
		routing_mark: strToInt(self_mark),

		server: hysteria_realm ? null : node.address,
		server_port: hysteria_realm ? null : strToInt(node.port),
		/* Hysteria(2) */
		server_ports: hysteria_realm ? null : node.hysteria_hopping_port,

		username: (node.type !== 'ssh') ? node.username : null,
		user: (node.type === 'ssh') ? node.username : null,
		password: node.password,

		/* Direct */
		override_address: node.override_address,
		override_port: strToInt(node.override_port),
		proxy_protocol: strToInt(node.proxy_protocol),
		/* AnyTLS */
		idle_session_check_interval: strToTime(node.anytls_idle_session_check_interval),
		idle_session_timeout: strToTime(node.anytls_idle_session_timeout),
		min_idle_session: strToInt(node.anytls_min_idle_session),
		/* Hysteria (2) */
		hop_interval: strToTime(node.hysteria_hop_interval),
		hop_interval_max: is_hysteria2 ? strToTime(node.hysteria2_hop_interval_max) : null,
		up_mbps: (is_hysteria1 && !hysteria1_up) ? 100 : strToInt(node.hysteria_up_mbps),
		down_mbps: (is_hysteria1 && !hysteria1_down) ? 100 : strToInt(node.hysteria_down_mbps),
		/* v1 takes a plain string, v2 takes { type, password } */
		obfs: is_hysteria1 ? (node.hysteria_obfs_password || null) :
			((is_hysteria2 && !isEmpty(node.hysteria_obfs_type)) ? {
				type: node.hysteria_obfs_type,
				password: node.hysteria_obfs_password
			} : null),
		auth: (is_hysteria1 && node.hysteria_auth_type === 'base64') ? node.hysteria_auth_payload : null,
		auth_str: (is_hysteria1 && node.hysteria_auth_type === 'string') ? node.hysteria_auth_payload : null,
		recv_window_conn: is_hysteria1 ? strToInt(node.hysteria_recv_window_conn) : null,
		recv_window: is_hysteria1 ? strToInt(node.hysteria_revc_window) : null,
		disable_mtu_discovery: is_hysteria1 ? strToBool(node.hysteria_disable_mtu_discovery) : null,
		/* Hysteria2 only */
		bbr_profile: is_hysteria2 ? (node.hysteria2_bbr_profile || null) : null,
		brutal_debug: is_hysteria2 ? strToBool(node.hysteria2_brutal_debug) : null,
		disable_chrome_parrot: is_hysteria2 ? strToBool(node.hysteria2_disable_chrome_parrot) : null,
		realm: hysteria_realm ? {
			server_url: node.hysteria2_realm_server_url,
			token: node.hysteria2_realm_token,
			realm_id: node.hysteria2_realm_id,
			stun_servers: normalizeList(node.hysteria2_realm_stun_servers),
			ip_version: strToInt(node.hysteria2_realm_ip_version),
			port_mapping: strToBool(node.hysteria2_realm_port_mapping) ? {
				enabled: true,
				timeout: strToTime(node.hysteria2_realm_port_mapping_timeout),
				lifetime: strToTime(node.hysteria2_realm_port_mapping_lifetime)
			} : null
		} : null,
		/* Shadowsocks */
		method: node.shadowsocks_encrypt_method,
		plugin: node.shadowsocks_plugin,
		plugin_opts: node.shadowsocks_plugin_opts,
		/* ShadowTLS / Socks */
		version: (node.type === 'shadowtls') ? strToInt(node.shadowtls_version) : ((node.type === 'socks') ? node.socks_version : null),
		/* SSH */
		client_version: node.ssh_client_version,
		host_key: node.ssh_host_key,
		host_key_algorithms: node.ssh_host_key_algo,
		private_key: node.ssh_priv_key,
		private_key_passphrase: node.ssh_priv_key_pp,
		/* Tuic */
		uuid: node.uuid,
		congestion_control: node.tuic_congestion_control,
		udp_relay_mode: node.tuic_udp_relay_mode,
		udp_over_stream: strToBool(node.tuic_udp_over_stream),
		zero_rtt_handshake: strToBool(node.tuic_enable_zero_rtt),
		heartbeat: strToTime(node.tuic_heartbeat),
		/* VLESS / VMess */
		flow: node.vless_flow,
		alter_id: strToInt(node.vmess_alterid),
		security: node.vmess_encrypt,
		global_padding: strToBool(node.vmess_global_padding),
		authenticated_length: strToBool(node.vmess_authenticated_length),
		packet_encoding: node.packet_encoding,

		multiplex: (node.multiplex === '1') ? {
			enabled: true,
			protocol: node.multiplex_protocol,
			max_connections: strToInt(node.multiplex_max_connections),
			min_streams: strToInt(node.multiplex_min_streams),
			max_streams: strToInt(node.multiplex_max_streams),
			padding: strToBool(node.multiplex_padding),
			brutal: (node.multiplex_brutal === '1') ? {
				enabled: true,
				up_mbps: strToInt(node.multiplex_brutal_up),
				down_mbps: strToInt(node.multiplex_brutal_down)
			} : null
		} : null,
		tls: (node.tls === '1') ? {
			enabled: true,
			server_name: node.tls_sni,
			insecure: strToBool(node.tls_insecure),
			alpn: node.tls_alpn,
			min_version: node.tls_min_version,
			max_version: node.tls_max_version,
			cipher_suites: node.tls_cipher_suites,
			certificate_path: node.tls_cert_path,
			fragment: strToBool(node.tls_fragment),
			fragment_fallback_delay: strToBool(node.tls_fragment) ?
				strToDuration(node.tls_fragment_fallback_delay) : null,
			record_fragment: strToBool(node.tls_record_fragment),
			spoof: tls_spoof_host,
			spoof_method: (tls_spoof_host && !isEmpty(node.tls_spoof_method)) ?
				node.tls_spoof_method : null,
			ech: (node.tls_ech === '1') ? {
				enabled: true,
				config: node.tls_ech_config,
				config_path: node.tls_ech_config_path
			} : null,
			utls: (!isEmpty(node.tls_utls) || tls_reality_on) ? {
				enabled: true,
				fingerprint: isEmpty(node.tls_utls) ? 'chrome' : node.tls_utls
			} : null,
			reality: (node.tls_reality === '1') ? {
				enabled: true,
				public_key: node.tls_reality_public_key,
				short_id: node.tls_reality_short_id
			} : null
		} : null,
		transport: !isEmpty(node.transport) ? {
			type: node.transport,
			host: node.http_host || node.httpupgrade_host || node.xhttp_host,
			path: node.http_path || node.ws_path || node.xhttp_path,
			headers: node.ws_host ? {
				Host: node.ws_host
			} : (is_xhttp ? xhttp_headers(node.xhttp_headers) : null),
			method: (node.transport === 'http') ? node.http_method : null,
			max_early_data: strToInt(node.websocket_early_data),
			early_data_header_name: node.websocket_early_data_header,
			service_name: node.grpc_servicename,
			idle_timeout: strToTime(node.http_idle_timeout),
			ping_timeout: strToTime(node.http_ping_timeout),
			permit_without_stream: strToBool(node.grpc_permit_without_stream),

			mode: is_xhttp ? (node.xhttp_mode || null) : null,
			domain_strategy: is_xhttp ? (node.xhttp_domain_strategy || null) : null,
			x_padding_bytes: is_xhttp ? xhttpPadding(node.xhttp_padding_bytes) : null,
			no_grpc_header: is_xhttp ? strToBool(node.xhttp_no_grpc_header) : null,
			sc_max_each_post_bytes: is_xhttp ? rangeValue(node.xhttp_sc_max_each_post_bytes) : null,
			sc_min_posts_interval_ms: is_xhttp ? rangeValue(node.xhttp_sc_min_posts_interval_ms) : null,
			sc_max_buffered_posts: is_xhttp ? strToInt(node.xhttp_sc_max_buffered_posts) : null,
			sc_stream_up_server_secs: is_xhttp ? rangeValue(node.xhttp_sc_stream_up_server_secs) : null,
			no_sse_header: is_xhttp ? strToBool(node.xhttp_no_sse_header) : null,
			uplink_http_method: is_xhttp ? xhttp_uplink_method(node.xhttp_method, xhttp_packet_up) : null,

			x_padding_obfs_mode: is_xhttp ? strToBool(node.xhttp_x_padding_obfs_mode) : null,
			x_padding_placement: is_xhttp ? (node.xhttp_x_padding_placement || null) : null,
			x_padding_key: is_xhttp ? (node.xhttp_x_padding_key || null) : null,
			x_padding_header: is_xhttp ? (node.xhttp_x_padding_header || null) : null,
			x_padding_method: is_xhttp ? (node.xhttp_x_padding_method || null) : null,

			session_placement: is_xhttp ? (node.xhttp_session_placement || null) : null,
			session_key: is_xhttp ? (node.xhttp_session_key || null) : null,

			seq_placement: is_xhttp ? (node.xhttp_seq_placement || null) : null,
			seq_key: is_xhttp ? (node.xhttp_seq_key || null) : null,

			uplink_data_placement: is_xhttp ? xhttp_uplink_data_placement(node.xhttp_uplink_data_placement, xhttp_packet_up) : null,
			uplink_data_key: is_xhttp ? (node.xhttp_uplink_data_key || null) : null,
			uplink_chunk_size: is_xhttp ? strToInt(node.xhttp_uplink_chunk_size) : null,

			download: (is_xhttp && (node.xhttp_download_host || node.xhttp_download_path || node.xhttp_download_server)) ? {
				host: node.xhttp_download_host || null,
				path: node.xhttp_download_path || null,
				headers: xhttp_headers(node.xhttp_download_headers),
				domain_strategy: node.xhttp_download_domain_strategy || null,
				x_padding_bytes: xhttpPadding(node.xhttp_download_padding_bytes || node.xhttp_padding_bytes),
				uplink_http_method: xhttp_uplink_method(node.xhttp_download_method, xhttp_packet_up),
				no_grpc_header: strToBool(node.xhttp_download_no_grpc_header),
				no_sse_header: strToBool(node.xhttp_download_no_sse_header),
				sc_max_each_post_bytes: rangeValue(node.xhttp_download_sc_max_each_post_bytes),
				sc_min_posts_interval_ms: rangeValue(node.xhttp_download_sc_min_posts_interval_ms),
				sc_max_buffered_posts: strToInt(node.xhttp_download_sc_max_buffered_posts),
				sc_stream_up_server_secs: rangeValue(node.xhttp_download_sc_stream_up_server_secs),

				x_padding_obfs_mode: strToBool(node.xhttp_download_x_padding_obfs_mode),
				x_padding_placement: node.xhttp_download_x_padding_placement || null,
				x_padding_key: node.xhttp_download_x_padding_key || null,
				x_padding_header: node.xhttp_download_x_padding_header || null,
				x_padding_method: node.xhttp_download_x_padding_method || null,

				session_placement: node.xhttp_download_session_placement || null,
				session_key: node.xhttp_download_session_key || null,

				seq_placement: node.xhttp_download_seq_placement || null,
				seq_key: node.xhttp_download_seq_key || null,

				uplink_data_placement: xhttp_uplink_data_placement(node.xhttp_download_uplink_data_placement, xhttp_packet_up),
				uplink_data_key: node.xhttp_download_uplink_data_key || null,
				uplink_chunk_size: strToInt(node.xhttp_download_uplink_chunk_size),

				xmux: (node.xhttp_download_xmux_max_concurrency || node.xhttp_download_xmux_max_connections ||
					node.xhttp_download_xmux_c_max_reuse_times || node.xhttp_download_xmux_h_max_request_times ||
					node.xhttp_download_xmux_h_max_reusable_secs || node.xhttp_download_xmux_h_keep_alive_period) ? normalize_xmux({
					max_concurrency: node.xhttp_download_xmux_max_concurrency,
					max_connections: rangeValue(node.xhttp_download_xmux_max_connections),
					c_max_reuse_times: rangeValue(node.xhttp_download_xmux_c_max_reuse_times),
					h_max_request_times: node.xhttp_download_xmux_h_max_request_times,
					h_max_reusable_secs: node.xhttp_download_xmux_h_max_reusable_secs,
					h_keep_alive_period: strToInt(node.xhttp_download_xmux_h_keep_alive_period)
				}) : null,

				/* hiddify-core's xhttp download leg always dials its own
				   server, an empty one is not inherited from the main leg */
				server: node.xhttp_download_server || node.address,
				server_port: strToInt(node.xhttp_download_server_port) || strToInt(node.port),
				tls: (node.xhttp_download_tls === '1') ? {
					enabled: true,
					server_name: node.xhttp_download_tls_server_name,
					alpn: node.xhttp_download_tls_alpn,
					insecure: strToBool(node.xhttp_download_tls_insecure)
				} : null,
				detour: node.xhttp_download_detour || null
			} : null,

			xmux: is_xhttp ? normalize_xmux({
				max_concurrency: node.xhttp_xmux_max_concurrency,
				max_connections: rangeValue(node.xhttp_xmux_max_connections),
				c_max_reuse_times: rangeValue(node.xhttp_xmux_c_max_reuse_times),
				h_max_request_times: node.xhttp_xmux_h_max_request_times,
				h_max_reusable_secs: node.xhttp_xmux_h_max_reusable_secs,
				h_keep_alive_period: strToInt(node.xhttp_xmux_h_keep_alive_period)
			}) : null
		} : null,
		udp_over_tcp: (node.udp_over_tcp === '1') ? {
			enabled: true,
			version: strToInt(node.udp_over_tcp_version)
		} : null,
		tcp_fast_open: strToBool(node.tcp_fast_open),
		tcp_multi_path: strToBool(node.tcp_multi_path),
		udp_fragment: strToBool(node.udp_fragment)
	};

	return outbound;
}



/* Config helper end */

const config = {};

function outbound_tag_defined(tag) {
	for (let out in (config.outbounds || []))
		if (out && out.tag === tag)
			return true;

	for (let ep in (config.endpoints || []))
		if (ep && ep.tag === tag)
			return true;

	return false;
}

/* Log */
config.log = {
	disabled: false,
	level: log_level,
	output: RUN_DIR + '/sing-box-c.log',
	timestamp: true
};

/* NTP */
if (!isEmpty(ntp_server))
	config.ntp = {
		enabled: true,
		server: ntp_server,
		detour: 'direct-out',
		domain_resolver: 'default-dns',
	};

/* DNS start */
/* Default settings */
config.dns = {
	servers: [
		{
			tag: 'default-dns',
			type: 'udp',
			server: wan_dns,
			detour: self_mark ? 'direct-out' : null
		},
		{
			tag: 'system-dns',
			type: 'local',
			detour: self_mark ? 'direct-out' : null
		}
	],
	rules: [],
	strategy: dns_default_strategy,
	client_subnet: null
};

/* Primary + fallback DNS servers are grouped behind a "fallback" type server */
function push_dns_server_with_fallback(tag, server_addr, default_protocol, fallback_list, detour, resolver_strategy) {
	const base = {
		domain_resolver: {
			server: 'default-dns',
			strategy: resolver_strategy
		},
		detour: detour
	};

	if (!length(fallback_list)) {
		push(config.dns.servers, {
			tag,
			...base,
			...parse_dnsserver(server_addr, default_protocol)
		});
		return;
	}

	const member_tags = [ `${tag}-primary` ];
	push(config.dns.servers, {
		tag: member_tags[0],
		...base,
		...parse_dnsserver(server_addr, default_protocol)
	});

	let idx = 0;
	for (let addr in fallback_list) {
		let member_tag = `${tag}-fallback-${idx++}`;
		push(config.dns.servers, {
			tag: member_tag,
			...base,
			...parse_dnsserver(addr, default_protocol)
		});
		push(member_tags, member_tag);
	}

	/* hiddify-core uses the "group" transport instead of the legacy
	   "fallback" one, the strategy is expressed through "mode" */
	push(config.dns.servers, {
		tag,
		type: 'group',
		servers: member_tags,
		mode: dns_fallback_strategy
	});
}

if (tailscale_enabled) {
	/* MagicDNS: the tailscale DNS server only answers tailnet hosts, the rule
	   has to be evaluated before every other DNS rule */
	push(config.dns.servers, {
		type: 'tailscale',
		tag: 'tailscale-dns',
		endpoint: tailscale_tag
	});
	push(config.dns.rules, {
		preferred_by: 'tailscale-dns',
		action: 'route',
		server: 'tailscale-dns'
	});

	/* the endpoint also works without a proxy node */
	if (isEmpty(main_node))
		config.dns.final = 'default-dns';
}

if (!isEmpty(main_node)) {
	/* Main DNS */
	push_dns_server_with_fallback('main-dns', dns_server, 'tcp', dns_server_fallback, main_out_tag,
		(ipv6_support !== '1') ? 'ipv4_only' : null);
	config.dns.final = 'main-dns';

	if (length(direct_domain_list))
		push(config.dns.rules, {
			rule_set: 'direct-domain',
			action: 'route',
			server: (routing_mode === 'bypass_mainland_china') ? 'china-dns' : 'default-dns'
		});

	/* Filter out SVCB/HTTPS queries for "exquisite" Apple devices */
	if (length(proxy_domain_list))
		push(config.dns.rules, {
			rule_set: 'proxy-domain',
			query_type: [64, 65],
			action: 'reject'
		});

	if (routing_mode === 'bypass_mainland_china') {
		push_dns_server_with_fallback('china-dns', china_dns_server, 'udp', china_dns_server_fallback,
			self_mark ? 'direct-out' : null, 'prefer_ipv6');

		if (length(proxy_domain_list))
			push(config.dns.rules, {
				rule_set: 'proxy-domain',
				action: 'route',
				server: 'main-dns'
			});

		push(config.dns.rules, {
			rule_set: 'geosite-cn',
			action: 'route',
			server: 'china-dns'
		});
		push(config.dns.rules, {
			type: 'logical',
			mode: 'and',
			rules: [
				{
					rule_set: 'geosite-noncn',
					invert: true
				},
				{
					rule_set: 'geoip-cn'
				}
			],
			action: 'route',
			server: 'china-dns'
		});
	}
}

/* DNS end */

/* Inbound start */
config.inbounds = [];

push(config.inbounds, {
	type: 'direct',
	tag: 'dns-in',
	listen: '::',
	listen_port: int(dns_port)
});

push(config.inbounds, {
	type: 'mixed',
	tag: 'mixed-in',
	listen: '::',
	listen_port: int(mixed_port),
	udp_timeout: strToTime(udp_timeout),
	set_system_proxy: false
});

if (match(proxy_mode, /redirect/))
	push(config.inbounds, {
		type: 'redirect',
		tag: 'redirect-in',

		listen: '::',
		listen_port: int(redirect_port)
	});
if (match(proxy_mode, /tproxy/) && !isEmpty(tproxy_port))
	push(config.inbounds, {
		type: 'tproxy',
		tag: 'tproxy-in',

		listen: '::',
		listen_port: int(tproxy_port),
		network: 'udp',
		udp_timeout: strToTime(udp_timeout)
	});
if (match(proxy_mode, /tun/))
	push(config.inbounds, {
		type: 'tun',
		tag: 'tun-in',

		interface_name: tun_name,
		address: (ipv6_support === '1') ? [tun_addr4, tun_addr6] : [tun_addr4],
		mtu: strToInt(tun_mtu),
		auto_route: false,
		udp_timeout: strToTime(udp_timeout)
	});
/* Inbound end */

/* Outbound start */
config.endpoints = [];

/* Tailscale endpoint */
if (tailscale_enabled)
	push(config.endpoints, {
		type: 'tailscale',
		tag: tailscale_tag,
		/* Talk to the coordination server and the peers directly: the
		   transparent proxy would otherwise intercept these connections and
		   the node never reaches the login state. */
		routing_mark: strToInt(self_mark),
		/* Resolve the coordination server with the WAN resolver instead of the
		   mainland one, which may answer with an unreachable address. */
		domain_resolver: {
			server: 'default-dns',
			strategy: dns_default_strategy
		},
		state_directory: HP_DIR + '/tailscale',
		taildrop_directory: HP_DIR + '/tailscale/taildrop',
		auth_key: tailscale_auth_key,
		control_url: tailscale_control_url,
		hostname: tailscale_hostname,
		accept_routes: tailscale_accept_routes,
		exit_node: tailscale_exit_node,
		exit_node_allow_lan_access: !isEmpty(tailscale_exit_node) ?
			tailscale_exit_node_allow_lan_access : null,
		advertise_routes: length(tailscale_advertise_routes) ? tailscale_advertise_routes : null,
		advertise_exit_node: tailscale_advertise_exit_node,
		listen_port: strToInt(tailscale_listen_port)
	});

/* Default outbounds */
config.outbounds = [
	{
		type: 'direct',
		tag: 'direct-out',
		routing_mark: strToInt(self_mark)
	},
	{
		type: 'block',
		tag: 'block-out'
	}
];

/* Main outbounds */
if (!isEmpty(main_node)) {
	let group_nodes = [];

	if (main_node === 'urltest') {
		const main_urltest_interval = uci.get(uciconfig, ucimain, 'main_urltest_interval');
		const main_urltest_tolerance = uci.get(uciconfig, ucimain, 'main_urltest_tolerance');

		push(config.outbounds, {
			type: 'urltest',
			tag: 'main-out',
			outbounds: map(main_urltest_nodes, (k) => node_out_tag(k)),
			interval: strToTime(main_urltest_interval),
			tolerance: strToInt(main_urltest_tolerance),
			/* keep the selected node until it fails instead of always picking the fastest */
			mode: strToBool(uci.get(uciconfig, ucimain, 'main_urltest_failover')) ? 'failover' : null,
			interrupt_exist_connections: strToBool(uci.get(uciconfig, ucimain, 'main_urltest_interrupt_exist_connections')),
			idle_timeout: (strToInt(main_urltest_interval) > 1800) ? `${main_urltest_interval * 2}s` : null,
		});
		group_nodes = main_urltest_nodes;
	} else if (main_node === 'fallback') {
		/* the members are dialed in order, the first that connects is used */
		push(config.outbounds, {
			type: 'fallback',
			tag: 'main-out',
			outbounds: map(main_fallback_nodes, (k) => node_out_tag(k)),
			blacklist_timeout: strToTime(uci.get(uciconfig, ucimain, 'main_fallback_blacklist_timeout'))
		});
		group_nodes = main_fallback_nodes;
	} else if (main_node === 'balancer') {
		/*
		 * The members and their delays come from the background monitoring, the
		 * group keeps no test schedule of its own.
		 */
		push(config.outbounds, {
			type: 'balancer',
			tag: 'main-out',
			outbounds: map(main_balancer_nodes, (k) => node_out_tag(k)),
			strategy: uci.get(uciconfig, ucimain, 'main_balancer_strategy') || 'round-robin',
			delay_acceptable_ratio: strToFloat(uci.get(uciconfig, ucimain, 'main_balancer_delay_acceptable_ratio')),
			tolerance: strToInt(uci.get(uciconfig, ucimain, 'main_balancer_tolerance')),
			tolerance_ratio: strToFloat(uci.get(uciconfig, ucimain, 'main_balancer_tolerance_ratio')),
			interrupt_exist_connections: strToBool(uci.get(uciconfig, ucimain, 'main_balancer_interrupt_exist_connections'))
		});
		group_nodes = main_balancer_nodes;
	} else {
		const main_node_cfg = uci.get_all(uciconfig, main_node) || {};
		if (main_node_cfg.type === 'wireguard') {
			push(config.endpoints, generate_endpoint(main_node_cfg));
			config.endpoints[length(config.endpoints)-1].tag = main_out_tag;
		} else {
			push(config.outbounds, generate_outbound(main_node_cfg));
			config.outbounds[length(config.outbounds)-1].tag = main_out_tag;
		}
	}

	for (let i in group_nodes) {
		const group_node = uci.get_all(uciconfig, i) || {};

		/* a node may already be emitted (main node, app rules) */
		if (isEmpty(group_node.type) || outbound_tag_defined(node_out_tag(i)))
			continue;

		if (group_node.type === 'wireguard') {
			push(config.endpoints, generate_endpoint(group_node));
			config.endpoints[length(config.endpoints)-1].tag = node_out_tag(i);
		} else {
			push(config.outbounds, generate_outbound(group_node));
			config.outbounds[length(config.outbounds)-1].tag = node_out_tag(i);
		}
	}
}

/* Outbound end */

/* Application routing helper start */

/*
 * The access control lists end up as ip_cidr / source_ip_cidr in the core
 * configuration. A single invalid entry makes sing-box reject the whole
 * configuration, and the service then fails to start with a generic error, so
 * every entry is validated first (cidr4/cidr6 also accept a bare address).
 * The syntax is narrowed as well: ubox accepts a few forms the core does not,
 * like a trailing slash without a prefix length.
 */
function valid_ip_list(values) {
	let valid = [];

	for (let value in values) {
		const addr = trim(value);
		if (isEmpty(addr))
			continue;

		if (match(addr, /^[0-9a-fA-F:.]+(\/[0-9]{1,3})?$/) &&
		    (validation('cidr4', addr) || validation('cidr6', addr))) {
			push(valid, addr);
			continue;
		}

		warn(`homeproxy: ignoring the invalid address "${addr}" of the access control lists.\n`);
	}

	return valid;
}

function rule_set_defined(tag) {
	for (let rs in config.route.rule_set)
		if (rs.tag === tag)
			return true;

	return false;
}

function add_node_outbound(id) {
	if (isEmpty(id) || outbound_tag_defined(node_out_tag(id)))
		return;

	const cfg = uci.get_all(uciconfig, id) || {};
	if (isEmpty(cfg.type))
		return;

	if (cfg.type === 'wireguard')
		push(config.endpoints, generate_endpoint(cfg));
	else
		push(config.outbounds, generate_outbound(cfg));
}

function valid_node_list(list) {
	let nodes = [];

	for (let id in normalizeList(list)) {
		const cfg = uci.get_all(uciconfig, id);

		if (!isEmpty(id) && type(cfg) === 'object' && !isEmpty(cfg.type) && !(id in nodes))
			push(nodes, id);
	}

	return nodes;
}

function app_rule_label(cfg) {
	if (cfg.source !== 'custom')
		return cfg.source;

	const name = trim(cfg.custom_service_name || '') || 'custom';
	return name + '-' + cfg['.name'];
}

/* Resolve the outbound an application rule should use */
function app_rule_outbound(cfg) {
	const node = cfg.node || 'main-out';

	switch (node) {
	case 'main-out':
		return main_out_tag;
	case 'direct-out':
		return 'direct-out';
	case 'reject-out':
		return 'block-out';
	case 'tailscale':
		/* the endpoint is optional, fall back to the main node when it is off */
		return tailscale_enabled ? tailscale_tag : main_out_tag;
	case 'urltest': {
		const nodes = valid_node_list(cfg.urltest_nodes);

		if (!length(nodes))
			return main_out_tag;

		const tag = 'app-' + app_rule_label(cfg) + '-out';

		if (!outbound_tag_defined(tag)) {
			push(config.outbounds, {
				type: 'urltest',
				tag,
				outbounds: map(nodes, (k) => node_out_tag(k)),
				interval: strToTime(cfg.urltest_interval || '120'),
				tolerance: strToInt(cfg.urltest_tolerance),
				interrupt_exist_connections: strToBool(cfg.urltest_interrupt_exist_connections),
				mode: strToBool(cfg.urltest_failover) ? 'failover' : null
			});
		}

		for (let id in nodes)
			add_node_outbound(id);

		return tag;
	}
	case 'fallback': {
		const nodes = valid_node_list(cfg.fallback_nodes);

		if (!length(nodes))
			return main_out_tag;

		const tag = 'app-' + app_rule_label(cfg) + '-out';

		if (!outbound_tag_defined(tag)) {
			push(config.outbounds, {
				type: 'fallback',
				tag,
				outbounds: map(nodes, (k) => node_out_tag(k)),
				blacklist_timeout: strToTime(cfg.fallback_blacklist_timeout)
			});
		}

		for (let id in nodes)
			add_node_outbound(id);

		return tag;
	}
	case 'balancer': {
		const nodes = valid_node_list(cfg.balancer_nodes);

		if (!length(nodes))
			return main_out_tag;

		const tag = 'app-' + app_rule_label(cfg) + '-out';

		if (!outbound_tag_defined(tag)) {
			push(config.outbounds, {
				type: 'balancer',
				tag,
				outbounds: map(nodes, (k) => node_out_tag(k)),
				strategy: cfg.balancer_strategy || 'round-robin',
				delay_acceptable_ratio: strToFloat(cfg.balancer_delay_acceptable_ratio),
				tolerance: strToInt(cfg.balancer_tolerance),
				tolerance_ratio: strToFloat(cfg.balancer_tolerance_ratio),
				interrupt_exist_connections: strToBool(cfg.balancer_interrupt_exist_connections)
			});
		}

		for (let id in nodes)
			add_node_outbound(id);

		return tag;
	}
	default:
		const node_cfg = uci.get_all(uciconfig, node);

		if (type(node_cfg) === 'object' && !isEmpty(node_cfg.type)) {
			add_node_outbound(node);
			return node_out_tag(node);
		}

		return main_out_tag;
	}
}
/* Application routing helper end */

/* Routing rules start */
/* Default settings */
config.route = {
	rules: [
		{
			inbound: 'dns-in',
			action: 'hijack-dns'
		},
		{
			action: 'sniff'
		}
	],
	rule_set: [],
	auto_detect_interface: isEmpty(default_interface) ? true : null,
	default_interface: default_interface
};

/* Avoid DNS loop, china-dns only exists with a main node */
config.route.default_domain_resolver = {
	action: 'route',
	server: (!isEmpty(main_node) && routing_mode === 'bypass_mainland_china') ?
		'china-dns' : 'default-dns',
	strategy: (ipv6_support !== '1') ? 'prefer_ipv4' : null
};

/* Tailscale routing: traffic coming from the tailnet is never re-proxied, and
   the connections that belong to the tailnet (MagicDNS names and peer
   addresses) are sent to the endpoint before any other rule can claim them. */
if (tailscale_enabled) {
	push(config.route.rules, {
		inbound: tailscale_tag,
		action: 'route',
		outbound: 'direct-out'
	});
	push(config.route.rules, {
		preferred_by: tailscale_tag,
		action: 'route',
		outbound: tailscale_tag
	});

	/* the endpoint also works without a proxy node */
	if (isEmpty(main_node))
		config.route.final = 'direct-out';
}

/* Routing rules */
if (!isEmpty(main_node)) {

	/* Direct list */
	if (length(direct_domain_list))
		push(config.route.rules, {
			rule_set: 'direct-domain',
			action: 'route',
			outbound: 'direct-out'
		});

	config.route.final = main_out_tag;

	/* Rule set */
	/* Direct list */
	if (length(direct_domain_list))
		push(config.route.rule_set, {
			type: 'inline',
			tag: 'direct-domain',
			rules: [
				{
					domain_keyword: direct_domain_list,
				}
			]
		});

	/* Proxy list */
	if (length(proxy_domain_list))
		push(config.route.rule_set, {
			type: 'inline',
			tag: 'proxy-domain',
			rules: [
				{
					domain_keyword: proxy_domain_list,
				}
			]
		});

	/* Application based routing rules */
	uci.foreach(uciconfig, uciapprule, (cfg) => {
		if (cfg.enabled !== '1' || isEmpty(cfg.source))
			return;

		const outbound = app_rule_outbound(cfg);
		const base_tag = 'app-rule-' + app_rule_label(cfg);
		let domain_tags = [], all_tags = [];

		const add_remote = (tag, format, url) => {
			if (rule_set_defined(tag))
				return;

			push(config.route.rule_set, {
				type: 'remote',
				tag,
				format,
				url
			});
		};

		if (cfg.source === 'custom') {
			const mode = cfg.custom_mode || 'url_domain';

			if (mode === 'domains') {
				let domains = [];

				for (let d in split(trim(cfg.custom_domains || ''), /\r?\n/)) {
					d = trim(d);
					if (!isEmpty(d))
						push(domains, d);
				}

				if (!length(domains))
					return;

				if (!rule_set_defined(base_tag))
					push(config.route.rule_set, {
						type: 'inline',
						tag: base_tag,
						rules: [ { domain_keyword: domains } ]
					});

				all_tags = [ base_tag ];
			} else {
				const format = (cfg.custom_format === 'source') ? 'source' : 'binary';
				let idx = 0;

				if (mode !== 'url_ip')
					for (let url in normalizeList(cfg.custom_url)) {
						if (isEmpty(url))
							continue;

						const tag = `${base_tag}-domain-${idx++}`;
						push(domain_tags, tag);
						push(all_tags, tag);
						add_remote(tag, format, url);
					}

				idx = 0;
				if (mode !== 'url_domain')
					for (let url in normalizeList(cfg.custom_url_ip)) {
						if (isEmpty(url))
							continue;

						const tag = `${base_tag}-ip-${idx++}`;
						push(all_tags, tag);
						add_remote(tag, format, url);
					}
			}
		} else {
			const urls = app_rule_urls[cfg.source];

			if (isEmpty(urls))
				return;

			if (!isEmpty(urls.domain)) {
				const tag = base_tag + '-domain';
				push(domain_tags, tag);
				push(all_tags, tag);
				add_remote(tag, 'binary', urls.domain);
			}

			if (!isEmpty(urls.ip)) {
				const tag = base_tag + '-ip';
				push(all_tags, tag);
				add_remote(tag, 'binary', urls.ip);
			}
		}

		if (!length(all_tags))
			return;

		push(config.route.rules, {
			rule_set: all_tags,
			action: 'route',
			outbound
		});

		/* Let the corresponding DNS server resolve these domains */
		if (!length(domain_tags))
			return;

		if (outbound === 'block-out')
			push(config.dns.rules, {
				rule_set: domain_tags,
				action: 'reject'
			});
		else
			push(config.dns.rules, {
				rule_set: domain_tags,
				action: 'route',
				server: (outbound === 'direct-out') ?
					((routing_mode === 'bypass_mainland_china') ? 'china-dns' : 'default-dns') : 'main-dns'
			});
	});

	if (routing_mode === 'bypass_mainland_china') {
		push(config.route.rule_set, {
			type: 'remote',
			tag: 'geoip-cn',
			format: 'binary',
			url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs'
		});
		push(config.route.rule_set, {
			type: 'remote',
			tag: 'geosite-cn',
			format: 'binary',
			url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/cn.srs'
		});
		push(config.route.rule_set, {
			type: 'remote',
			tag: 'geosite-noncn',
			format: 'binary',
			url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs'
		});

		/*
		 * The firewall no longer returns China IPs, the core has to split the
		 * traffic. Order matters: the forced proxy entries first, then China
		 * domains and China IPs go direct, everything else falls to the main node.
		 */
		if (!bypass_china_ip) {
			/* proxy destinations of the access control tab: the firewall sends them
			   to the core regardless of the China IP list */
			const force_dst = valid_ip_list([
				...normalizeList(uci.get(uciconfig, ucicontrol, 'wan_proxy_ipv4_ips')),
				...normalizeList(uci.get(uciconfig, ucicontrol, 'wan_proxy_ipv6_ips'))
			]);
			if (length(force_dst))
				push(config.route.rules, {
					ip_cidr: force_dst,
					action: 'route',
					outbound: main_out_tag
				});

			/* global proxy devices by MAC: the core resolves the device from the
			   neighbor table (or the DHCP leases) on its own, no IP mapping */
			const force_mac = filter(
				normalizeList(uci.get(uciconfig, ucicontrol, 'lan_global_proxy_mac_addrs')),
				(v) => (type(v) === 'string' && !isEmpty(trim(v)))
			);
			if (length(force_mac))
				push(config.route.rules, {
					source_mac_address: force_mac,
					action: 'route',
					outbound: main_out_tag
				});

			/* global proxy devices by IP */
			const force_src = valid_ip_list([
				...normalizeList(uci.get(uciconfig, ucicontrol, 'lan_global_proxy_ipv4_ips')),
				...normalizeList(uci.get(uciconfig, ucicontrol, 'lan_global_proxy_ipv6_ips'))
			]);
			if (length(force_src))
				push(config.route.rules, {
					source_ip_cidr: force_src,
					action: 'route',
					outbound: main_out_tag
				});

			/* the proxy domain list wins over the China rule sets */
			if (length(proxy_domain_list))
				push(config.route.rules, {
					rule_set: 'proxy-domain',
					action: 'route',
					outbound: main_out_tag
				});

			push(config.route.rules, {
				rule_set: [ 'geosite-cn', 'geoip-cn' ],
				action: 'route',
				outbound: 'direct-out'
			});
		}
	}

	if (isEmpty(config.route.rule_set))
		config.route.rule_set = null;
}

/* Routing rules end */

/* Normalize empty collections */
if (config.endpoints && isEmpty(config.endpoints))
	config.endpoints = null;
if (config.route.rule_set && isEmpty(config.route.rule_set))
	config.route.rule_set = null;
if (config.dns.rules && isEmpty(config.dns.rules))
	config.dns.rules = null;

/*
 * Remote rule-sets download through the main outbound. They share one HTTP
 * client instead of carrying an inline one each: the inline option is the
 * replacement of "download_detour", which is deprecated since sing-box 1.14,
 * and an undefined default client is deprecated as well.
 */
if (config.route.rule_set && outbound_tag_defined(main_out_tag)) {
	config.http_clients = [
		{
			tag: 'rule-set-client',
			detour: main_out_tag
		}
	];
	config.route.default_http_client = 'rule-set-client';
}

/* Experimental start */
/*
 * The cache file keeps the DNS cache (and the API state, once a clash api is
 * configured) across restarts, so it is stored in /etc instead of the runtime
 * directory which is wiped on every reboot.
 */
config.experimental = {
	cache_file: {
		enabled: true,
		path: HP_DIR + '/cache/cache.db',
		store_dns: true
	}
};
/* Unified delay measuring (dns + tcp + tls + request) for all outbounds */
if (!isEmpty(main_node))
	config.experimental.unified_delay = {
		enabled: true
	};
/*
 * Clash API: the LuCI page reads the current node delay from it. It always
 * listens on the dashboard port plus one, on the loopback interface only.
 */
config.experimental.clash_api = {
	external_controller: `127.0.0.1:${dashboard_port + 1}`,
	secret: dashboard_secret
};
/* Experimental end */

/* API service: serves the dashboard and answers the API queries, the Tailscale
   login state is queried through it as well */
const api_console_enabled = dashboard_enabled || main_node === 'urltest' ||
	main_node === 'fallback' || main_node === 'balancer' || tailscale_enabled;

if (api_console_enabled)
	config.services = [
		{
			type: 'api',
			tag: 'api-dashboard',
			/* only expose it on the network when the dashboard is enabled */
			listen: dashboard_enabled ? '::' : '127.0.0.1',
			listen_port: dashboard_port,
			secret: dashboard_secret,
			dashboard: dashboard_enabled ? {
				enabled: true,
				path: dashboard_path
			} : null
		}
	];
/* API service end */

system('mkdir -p ' + RUN_DIR);
writefile(RUN_DIR + '/sing-box-c.json', sprintf('%.J\n', removeBlankAttrs(config)));
