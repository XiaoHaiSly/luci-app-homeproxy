#!/usr/bin/ucode

'use strict';

import { readfile } from 'fs';
import { connect } from 'ubus';
import { cursor } from 'uci';

import {
	createNodeLabelRegistry, isEmpty, parseURL, reserveUniqueLabel,
	strToBool, strToInt, strToTime,
	removeBlankAttrs, atomicWrite, validation, HP_DIR, RUN_DIR
} from 'homeproxy';

const ubus = connect();

const uci = cursor();

const uciconfig = 'homeproxy';
uci.load(uciconfig);

const uciinfra = 'infra',
      ucimain = 'config',
      ucicontrol = 'control';

const ucinode = 'node';

const outbound_tags = createNodeLabelRegistry();
const node_outbound_tags = {};
uci.foreach(uciconfig, ucinode, (cfg) => {
	let label = trim(cfg.label ?? '');
	if (!isEmpty(label))
		label = replace(label, /[\r\n\t]+/g, ' ');

	node_outbound_tags[cfg['.name']] = reserveUniqueLabel(
		outbound_tags,
		label,
		`cfg-${cfg['.name']}-out`
	);
});

function node_out_tag(id) {
	return node_outbound_tags[id] || `cfg-${id}-out`;
}

function first_valid_node() {
	let result = null;
	uci.foreach(uciconfig, ucinode, (cfg) => {
		if (!result && cfg?.['.name'])
			result = cfg['.name'];
	});
	return result;
}

function valid_node_list(list) {
	let result = [];
	for (let id in list) {
		if (uci.get_all(uciconfig, id)?.type)
			push(result, id);
	}
	return result;
}

const routing_mode = uci.get(uciconfig, ucimain, 'routing_mode') || 'bypass_mainland_china';
const proxy_mode = uci.get(uciconfig, ucimain, 'proxy_mode') || 'tun';
const gfwlist_tun = (routing_mode === 'gfwlist' && match(proxy_mode, /tun/));
const china_dns_enabled = (routing_mode === 'bypass_mainland_china' || gfwlist_tun);

let wan_dns = ubus.call('network.interface', 'status', {'interface': 'wan'})?.['dns-server']?.[0];
if (!wan_dns)
	wan_dns = (routing_mode in ['proxy_mainland_china', 'global']) ? '8.8.8.8' : '223.5.5.5';

const dns_port = uci.get(uciconfig, uciinfra, 'dns_port') || '5333';

const ntp_server = uci.get(uciconfig, uciinfra, 'ntp_server') || 'time.apple.com';

const ipv6_support = uci.get(uciconfig, ucimain, 'ipv6_support') || '0';

let main_node, main_udp_node, dedicated_udp_node,
    dns_server, china_dns_server, dns_default_strategy,
    direct_domain_list, proxy_domain_list;

const main_node_setting = uci.get(uciconfig, ucimain, 'main_node') || 'nil';

main_node = main_node_setting;
main_udp_node = uci.get(uciconfig, ucimain, 'main_udp_node') || 'nil';
const first_node_id = first_valid_node();
if (main_node !== 'nil' && main_node !== 'core_only' && main_node !== 'urltest' && !uci.get_all(uciconfig, main_node)?.type)
	main_node = first_node_id || 'nil';
if (main_udp_node !== 'nil' && main_udp_node !== 'same' && main_udp_node !== 'urltest' && !uci.get_all(uciconfig, main_udp_node)?.type)
	main_udp_node = first_node_id || 'nil';
dedicated_udp_node = !isEmpty(main_udp_node) && !(main_udp_node in ['same', main_node]);

dns_server = uci.get(uciconfig, ucimain, 'dns_server');
if (isEmpty(dns_server) || dns_server === 'wan')
	dns_server = wan_dns;

if (china_dns_enabled) {
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

const default_interface = uci.get(uciconfig, ucicontrol, 'bind_interface');

let routing_port = uci.get(uciconfig, ucimain, 'routing_port');
if (routing_port === 'common')
	routing_port = uci.get(uciconfig, uciinfra, 'common_port') || '';

let config_included_interfaces = null;
const listen_interfaces = uci.get(uciconfig, ucicontrol, 'listen_interfaces');
if (type(listen_interfaces) === 'array' && length(listen_interfaces))
	config_included_interfaces = listen_interfaces;

const mixed_port = uci.get(uciconfig, uciinfra, 'mixed_port') || '5330';

let self_mark, redirect_port, tproxy_port, tun_name,
    tun_addr4, tun_addr6, tun_mtu, tcpip_stack,
    udp_timeout;

udp_timeout = uci.get(uciconfig, 'infra', 'udp_timeout');

if (match(proxy_mode, /redirect/)) {
	self_mark = uci.get(uciconfig, 'infra', 'self_mark') || '100';
	redirect_port = uci.get(uciconfig, 'infra', 'redirect_port') || '5331';
}
if (match(proxy_mode, /tproxy/))
	tproxy_port = uci.get(uciconfig, 'infra', 'tproxy_port') || '5332';
if (match(proxy_mode, /tun/)) {

	tun_name = uci.get(uciconfig, uciinfra, 'tun_name') || 'singtun0';
	tun_addr4 = uci.get(uciconfig, uciinfra, 'tun_addr4') || '172.19.0.1/30';
	tun_addr6 = uci.get(uciconfig, uciinfra, 'tun_addr6') || 'fdfe:dcba:9876::1/126';
	tun_mtu = uci.get(uciconfig, uciinfra, 'tun_mtu') || '9000';
	tcpip_stack = uci.get(uciconfig, ucimain, 'tcpip_stack') || 'system';
}

const log_level = uci.get(uciconfig, ucimain, 'log_level') || 'warn';

const dashboard_path = HP_DIR + '/dashboard';
const dashboard_enabled = !isEmpty(readfile(dashboard_path + '/index.html')),
      dashboard_port = strToInt(uci.get(uciconfig, ucimain, 'dashboard_port')) || 9096,
      dashboard_secret = uci.get(uciconfig, ucimain, 'dashboard_secret');

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

function generate_outbound(node) {
	if (type(node) !== 'object' || isEmpty(node))
		return null;

	const outbound = {
		type: node.type,
		tag: node_out_tag(node['.name']),
		routing_mark: match(proxy_mode, /redirect/) ? strToInt(self_mark) : null,

		server: node.address,
		server_port: strToInt(node.port),
		server_ports: node.hysteria_hopping_port,

		username: (node.type !== 'ssh') ? node.username : null,
		user: (node.type === 'ssh') ? node.username : null,
		password: node.password,

		proxy_protocol: strToInt(node.proxy_protocol),
		idle_session_check_interval: strToTime(node.anytls_idle_session_check_interval),
		idle_session_timeout: strToTime(node.anytls_idle_session_timeout),
		min_idle_session: strToInt(node.anytls_min_idle_session),
		hop_interval: strToTime(node.hysteria_hop_interval),
		up_mbps: strToInt(node.hysteria_up_mbps),
		down_mbps: strToInt(node.hysteria_down_mbps),
		obfs: node.hysteria_obfs_type ? {
			type: node.hysteria_obfs_type,
			password: node.hysteria_obfs_password
		} : node.hysteria_obfs_password,
		auth: (node.hysteria_auth_type === 'base64') ? node.hysteria_auth_payload : null,
		auth_str: (node.hysteria_auth_type === 'string') ? node.hysteria_auth_payload : null,
		stream_receive_window: strToInt(node.hysteria_recv_window_conn),
		connection_receive_window: strToInt(node.hysteria_recv_window),
		disable_path_mtu_discovery: strToBool(node.hysteria_disable_mtu_discovery),
		method: node.shadowsocks_encrypt_method,
		plugin: node.shadowsocks_plugin,
		plugin_opts: node.shadowsocks_plugin_opts,
		version: (node.type === 'shadowtls') ? strToInt(node.shadowtls_version) : ((node.type === 'socks') ? node.socks_version : null),
		client_version: node.ssh_client_version,
		host_key: node.ssh_host_key,
		host_key_algorithms: node.ssh_host_key_algo,
		private_key: node.ssh_priv_key,
		private_key_passphrase: node.ssh_priv_key_pp,
		uuid: node.uuid,
		congestion_control: node.tuic_congestion_control,
		udp_relay_mode: node.tuic_udp_relay_mode,
		udp_over_stream: strToBool(node.tuic_udp_over_stream),
		zero_rtt_handshake: strToBool(node.tuic_enable_zero_rtt),
		heartbeat: strToTime(node.tuic_heartbeat),
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
			ech: (node.tls_ech === '1') ? {
				enabled: true,
				config: node.tls_ech_config,
				config_path: node.tls_ech_config_path
			} : null,
			utls: !isEmpty(node.tls_utls) ? {
				enabled: true,
				fingerprint: node.tls_utls
			} : null,
			reality: (node.tls_reality === '1') ? {
				enabled: true,
				public_key: node.tls_reality_public_key,
				short_id: node.tls_reality_short_id
			} : null
		} : null,
		transport: !isEmpty(node.transport) ? {
			type: node.transport,
			host: node.http_host || node.httpupgrade_host,
			path: node.http_path || node.ws_path,
			headers: node.ws_host ? {
				Host: node.ws_host
			} : null,
			method: node.http_method,
			max_early_data: strToInt(node.websocket_early_data),
			early_data_header_name: node.websocket_early_data_header,
			service_name: node.grpc_servicename,
			idle_timeout: strToTime(node.http_idle_timeout),
			ping_timeout: strToTime(node.http_ping_timeout),
			permit_without_stream: strToBool(node.grpc_permit_without_stream)
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

const local_interface_cidrs = [];
const ifdump = ubus.call('network.interface', 'dump', {}) || {};
for (let iface in (ifdump.interface || [])) {
	for (let a in (iface['ipv4-address'] || [])) {
		if (!isEmpty(a.address))
			push(local_interface_cidrs, `${a.address}/32`);
	}
	for (let a in (iface['ipv6-address'] || [])) {
		if (!isEmpty(a.address))
			push(local_interface_cidrs, `${a.address}/128`);
	}
}

const config = {};

config.log = {
	disabled: false,
	level: log_level,
	output: RUN_DIR + '/sing-box-c.log',
	timestamp: true
};

if (!isEmpty(ntp_server))
	config.ntp = {
		enabled: true,
		server: ntp_server,
		detour: 'direct-out',
		domain_resolver: 'default-dns',
	};

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
			neighbor_domain: ['.', '.lan'],
			detour: self_mark ? 'direct-out' : null
		}
	],
	rules: [
		{
			domain_suffix: ['.lan', '.local'],
			action: 'route',
			server: 'system-dns'
		}
	],
	reverse_mapping: true,
	strategy: dns_default_strategy,
	optimistic: true,
	cache_capacity: 4096,
	timeout: '10s',
	client_subnet: null
};

if (!isEmpty(main_node)) {
	push(config.dns.servers, {
		tag: 'main-dns',
		domain_resolver: {
			server: 'default-dns',
			strategy: (ipv6_support !== '1') ? 'ipv4_only' : null
		},
		detour: 'main-out',
		...parse_dnsserver(dns_server, 'tcp')
	});
	config.dns.final = gfwlist_tun ? 'china-dns' : 'main-dns';

	if (gfwlist_tun)
		push(config.dns.rules, {
			rule_set: 'gfw-list',
			action: 'route',
			server: 'main-dns'
		});

	if (length(direct_domain_list))
		push(config.dns.rules, {
			rule_set: 'direct-domain',
			action: 'route',
			server: china_dns_enabled ? 'china-dns' : 'default-dns'
		});

	const gfwlist_non_tun = (routing_mode === 'gfwlist' && !gfwlist_tun);
	if (gfwlist_non_tun || length(proxy_domain_list))
		push(config.dns.rules, {
			rule_set: gfwlist_non_tun ? null : 'proxy-domain',
			query_type: [64, 65],
			action: 'reject'
		});

	if (china_dns_enabled) {
		push(config.dns.servers, {
			tag: 'china-dns',
			domain_resolver: {
				server: 'default-dns',
				strategy: 'prefer_ipv6'
			},
			detour: self_mark ? 'direct-out' : null,
			...parse_dnsserver(china_dns_server)
		});

		if (length(proxy_domain_list))
			push(config.dns.rules, {
				rule_set: 'proxy-domain',
				action: 'route',
				server: 'main-dns'
			});
	}

	if (routing_mode === 'bypass_mainland_china') {
		push(config.dns.rules, {
			rule_set: 'geosite-cn',
			action: 'route',
			server: 'china-dns'
		});
		push(config.dns.rules, {
			rule_set: 'geosite-noncn',
			invert: true,
			action: 'evaluate',
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
					rule_set: 'geoip-cn',
					match_response: true
				}
			],
			action: 'route',
			server: 'china-dns'
		});
	}
}

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
if (match(proxy_mode, /tproxy/))
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
		auto_route: true,
		udp_timeout: strToTime(udp_timeout),
		stack: tcpip_stack,
		auto_redirect: true,
		exclude_mptcp: true,
		dns_mode: 'hijack',
		include_interface: config_included_interfaces,
		route_exclude_address: length(local_interface_cidrs) ? local_interface_cidrs : null
	});

config.endpoints = [];

config.outbounds = [
	{
		type: 'direct',
		tag: 'direct-out',
		routing_mark: match(proxy_mode, /redirect/) ? strToInt(self_mark) : null
	},
	{
		type: 'block',
		tag: 'block-out'
	}
];

if (!isEmpty(main_node)) {
	let urltest_nodes = [];

	if (main_node === 'urltest') {
		const main_urltest_nodes = valid_node_list(uci.get(uciconfig, ucimain, 'main_urltest_nodes') || []);
		const main_urltest_interval = uci.get(uciconfig, ucimain, 'main_urltest_interval');
		const main_urltest_tolerance = uci.get(uciconfig, ucimain, 'main_urltest_tolerance');
		const main_urltest_interrupt = uci.get(uciconfig, ucimain, 'main_urltest_interrupt_exist_connections');

		if (length(main_urltest_nodes)) {
			push(config.outbounds, {
				type: 'urltest',
				tag: 'main-out',
				outbounds: map(main_urltest_nodes, (k) => node_out_tag(k)),
				interval: strToTime(main_urltest_interval),
				tolerance: strToInt(main_urltest_tolerance),
				idle_timeout: (strToInt(main_urltest_interval) > 1800) ? `${main_urltest_interval * 2}s` : null,
				interrupt_exist_connections: (main_urltest_interrupt === '1') ? true : null,
			});
			urltest_nodes = main_urltest_nodes;
		} else if (first_node_id) {

			const fallback_cfg = uci.get_all(uciconfig, first_node_id) || {};
			if (fallback_cfg.type === 'wireguard') {
				push(config.endpoints, generate_endpoint(fallback_cfg));
				config.endpoints[length(config.endpoints)-1].tag = 'main-out';
			} else {
				push(config.outbounds, generate_outbound(fallback_cfg));
				config.outbounds[length(config.outbounds)-1].tag = 'main-out';
			}
			main_node = first_node_id;
		}
	} else {
		const main_node_cfg = uci.get_all(uciconfig, main_node) || {};
		if (main_node_cfg.type === 'wireguard') {
			push(config.endpoints, generate_endpoint(main_node_cfg));
			config.endpoints[length(config.endpoints)-1].tag = 'main-out';
		} else if (main_node_cfg.type) {
			push(config.outbounds, generate_outbound(main_node_cfg));
			config.outbounds[length(config.outbounds)-1].tag = 'main-out';
		}
	}

	if (main_udp_node === 'urltest') {
		const main_udp_urltest_nodes = valid_node_list(uci.get(uciconfig, ucimain, 'main_udp_urltest_nodes') || []);
		const main_udp_urltest_interval = uci.get(uciconfig, ucimain, 'main_udp_urltest_interval');
		const main_udp_urltest_tolerance = uci.get(uciconfig, ucimain, 'main_udp_urltest_tolerance');
		const main_udp_urltest_interrupt = uci.get(uciconfig, ucimain, 'main_udp_urltest_interrupt_exist_connections');

		if (length(main_udp_urltest_nodes)) {
			push(config.outbounds, {
				type: 'urltest',
				tag: 'main-udp-out',
				outbounds: map(main_udp_urltest_nodes, (k) => node_out_tag(k)),
				interval: strToTime(main_udp_urltest_interval),
				tolerance: strToInt(main_udp_urltest_tolerance),
				idle_timeout: (strToInt(main_udp_urltest_interval) > 1800) ? `${main_udp_urltest_interval * 2}s` : null,
				interrupt_exist_connections: (main_udp_urltest_interrupt === '1') ? true : null,
			});
			urltest_nodes = [...urltest_nodes, ...filter(main_udp_urltest_nodes, (l) => !~index(urltest_nodes, l))];
		} else if (main_udp_node !== 'nil' && first_node_id && main_node !== 'nil') {
			main_udp_node = 'same';
		}
	} else if (dedicated_udp_node) {
		const main_udp_node_cfg = uci.get_all(uciconfig, main_udp_node) || {};
		if (main_udp_node_cfg.type === 'wireguard') {
			push(config.endpoints, generate_endpoint(main_udp_node_cfg));
			config.endpoints[length(config.endpoints)-1].tag = 'main-udp-out';
		} else if (main_udp_node_cfg.type) {
			push(config.outbounds, generate_outbound(main_udp_node_cfg));
			config.outbounds[length(config.outbounds)-1].tag = 'main-udp-out';
		}
	}

	for (let i in urltest_nodes) {
		const urltest_node = uci.get_all(uciconfig, i) || {};
		if (urltest_node.type === 'wireguard') {
			push(config.endpoints, generate_endpoint(urltest_node));
			config.endpoints[length(config.endpoints)-1].tag = node_out_tag(i);
		} else {
			push(config.outbounds, generate_outbound(urltest_node));
			config.outbounds[length(config.outbounds)-1].tag = node_out_tag(i);
		}
	}
}

dedicated_udp_node = !isEmpty(main_udp_node) && !(main_udp_node in ['same', main_node]);

if (isEmpty(config.endpoints))
	config.endpoints = null;

if (!isEmpty(main_node))
	config.http_clients = [
		{
			tag: 'main-out',
			detour: 'main-out'
		}
	];

function parseRoutePorts(value) {
	const result = { ports: [], ranges: [] };
	if (isEmpty(value))
		return result;

	for (let item in split(value, ',')) {
		item = trim(item);
		if (isEmpty(item))
			continue;

		if (match(item, /^\d+$/)) {
			const port = int(item);
			if (port > 0 && port < 65536) push(result.ports, port);
		} else if (match(item, /^\d+[-:]\d+$/)) {
			const bounds = split(item, /[-:]/);
			const start = int(bounds[0]);
			const end = int(bounds[1]);
			if (start > 0 && start < 65536 && end > 0 && end < 65536 && start <= end)
				push(result.ranges, `${start}:${end}`);
		}
	}
	return result;
}

function appendSourceRule(rules, sources, action, extra) {
	extra = extra || {};
	if (isEmpty(sources.ip) && isEmpty(sources.mac))
		return false;

	let matchers = [];
	if (!isEmpty(sources.ip))
		push(matchers, { source_ip_cidr: sources.ip });
	if (!isEmpty(sources.mac))
		push(matchers, { source_mac_address: sources.mac });

	let matcher = (length(matchers) === 1) ? matchers[0] : {
		type: 'logical',
		mode: 'or',
		rules: matchers
	};

	push(rules, { inbound: 'tun-in', ...matcher, ...extra, action });
	return true;
}

function sourceList(ip, mac) {
	return {
		ip: (type(ip) === 'array') ? ip : (!isEmpty(ip) ? [ip] : []),
		mac: (type(mac) === 'array') ? mac : (!isEmpty(mac) ? [mac] : [])
	};
}

const route_prefilter_rules = [];
let needs_neighbor = false;

if (!isEmpty(main_node))
	push(route_prefilter_rules, { inbound: 'tun-in', network: 'icmp', action: 'route', outbound: 'direct-out' });

if (match(proxy_mode, /tun/) && !isEmpty(main_node)) {

	const route_ports = parseRoutePorts(routing_port);
	if (length(route_ports.ports) || length(route_ports.ranges)) {
		let selectors = [];
		if (length(route_ports.ports)) push(selectors, { port: route_ports.ports });
		if (length(route_ports.ranges)) push(selectors, { port_range: route_ports.ranges });
		const matcher = (length(selectors) === 1) ? selectors[0] : { type: 'logical', mode: 'or', rules: selectors };
		push(route_prefilter_rules, { inbound: 'tun-in', ...matcher, invert: true, action: 'bypass' });
	}
	const lan_proxy_mode = uci.get(uciconfig, ucicontrol, 'lan_proxy_mode') || 'disabled';
	const lan_proxy_ips = uci.get(uciconfig, ucicontrol, 'lan_proxy_ipv4_ips') || [];
	const lan_proxy_ips6 = uci.get(uciconfig, ucicontrol, 'lan_proxy_ipv6_ips') || [];
	const lan_proxy_macs = uci.get(uciconfig, ucicontrol, 'lan_proxy_mac_addrs') || [];
	const lan_direct_ips = uci.get(uciconfig, ucicontrol, 'lan_direct_ipv4_ips') || [];
	const lan_direct_ips6 = uci.get(uciconfig, ucicontrol, 'lan_direct_ipv6_ips') || [];
	const lan_direct_macs = uci.get(uciconfig, ucicontrol, 'lan_direct_mac_addrs') || [];
	const lan_global_ips = uci.get(uciconfig, ucicontrol, 'lan_global_proxy_ipv4_ips') || [];
	const lan_global_ips6 = uci.get(uciconfig, ucicontrol, 'lan_global_proxy_ipv6_ips') || [];
	const lan_global_macs = uci.get(uciconfig, ucicontrol, 'lan_global_proxy_mac_addrs') || [];
	const lan_gaming_ips = uci.get(uciconfig, ucicontrol, 'lan_gaming_mode_ipv4_ips') || [];
	const lan_gaming_ips6 = uci.get(uciconfig, ucicontrol, 'lan_gaming_mode_ipv6_ips') || [];
	const lan_gaming_macs = uci.get(uciconfig, ucicontrol, 'lan_gaming_mode_mac_addrs') || [];

	function combinedSource(ip4, ip6, mac) {
		let ips = [];
		if (type(ip4) === 'array') ips = [...ips, ...ip4];
		else if (!isEmpty(ip4)) push(ips, ip4);
		if (type(ip6) === 'array') ips = [...ips, ...ip6];
		else if (!isEmpty(ip6)) push(ips, ip6);
		return sourceList(ips, mac);
	}

	if (lan_proxy_mode === 'except_listed') {
		const direct_list = combinedSource(lan_direct_ips, lan_direct_ips6, lan_direct_macs);
		appendSourceRule(route_prefilter_rules, direct_list, 'bypass');
		needs_neighbor = needs_neighbor || !isEmpty(direct_list.mac);
	}

	const wan_proxy_ips = uci.get(uciconfig, ucicontrol, 'wan_proxy_ipv4_ips') || [];
	const wan_proxy_ips6 = uci.get(uciconfig, ucicontrol, 'wan_proxy_ipv6_ips') || [];
	const wan_direct_ips = uci.get(uciconfig, ucicontrol, 'wan_direct_ipv4_ips') || [];
	const wan_direct_ips6 = uci.get(uciconfig, ucicontrol, 'wan_direct_ipv6_ips') || [];
	if (!isEmpty(wan_proxy_ips) || !isEmpty(wan_proxy_ips6))
		push(route_prefilter_rules, { inbound: 'tun-in', ip_cidr: [...((type(wan_proxy_ips) === 'array') ? wan_proxy_ips : [wan_proxy_ips]), ...((type(wan_proxy_ips6) === 'array') ? wan_proxy_ips6 : [wan_proxy_ips6])], action: 'route', outbound: 'main-out' });
	if (!isEmpty(wan_direct_ips) || !isEmpty(wan_direct_ips6))
		push(route_prefilter_rules, { inbound: 'tun-in', ip_cidr: [...((type(wan_direct_ips) === 'array') ? wan_direct_ips : [wan_direct_ips]), ...((type(wan_direct_ips6) === 'array') ? wan_direct_ips6 : [wan_direct_ips6])], action: 'bypass' });

	if (lan_proxy_mode !== 'listed_only') {
		const global_proxy = combinedSource(lan_global_ips, lan_global_ips6, lan_global_macs);
		appendSourceRule(route_prefilter_rules, global_proxy, 'route', { outbound: 'main-out' });
		needs_neighbor = needs_neighbor || !isEmpty(global_proxy.mac);

		const gaming = combinedSource(lan_gaming_ips, lan_gaming_ips6, lan_gaming_macs);
		if (main_udp_node === 'urltest' || dedicated_udp_node)
			appendSourceRule(route_prefilter_rules, gaming, 'route', { outbound: 'main-udp-out' });
		else
			appendSourceRule(route_prefilter_rules, gaming, 'route', { outbound: 'main-out' });
		needs_neighbor = needs_neighbor || !isEmpty(gaming.mac);
	}

	if (lan_proxy_mode === 'listed_only') {
		const proxy_list = combinedSource(lan_proxy_ips, lan_proxy_ips6, lan_proxy_macs);
		needs_neighbor = needs_neighbor || !isEmpty(proxy_list.mac);

		const router_source_cidrs = [];
		for (let iface in (ifdump.interface || [])) {
			for (let a in (iface['ipv4-address'] || []))
				if (!isEmpty(a.address)) push(router_source_cidrs, `${a.address}/32`);
			for (let a in (iface['ipv6-address'] || []))
				if (!isEmpty(a.address)) push(router_source_cidrs, `${a.address}/128`);
		}
		if (length(router_source_cidrs))
			push(route_prefilter_rules, { inbound: 'tun-in', source_ip_cidr: router_source_cidrs, action: 'route', outbound: 'main-out' });

		if (!isEmpty(proxy_list.ip) || !isEmpty(proxy_list.mac)) {
			let matchers = [];
			if (!isEmpty(proxy_list.ip)) push(matchers, { source_ip_cidr: proxy_list.ip });
			if (!isEmpty(proxy_list.mac)) push(matchers, { source_mac_address: proxy_list.mac });
			const matcher = (length(matchers) === 1) ? matchers[0] : { type: 'logical', mode: 'or', rules: matchers };
			push(route_prefilter_rules, { inbound: 'tun-in', ...matcher, invert: true, action: 'bypass' });
		}
	}

}

config.route = {
	rules: [
		...route_prefilter_rules,
		{
			action: 'sniff'
		},
		{
			inbound: 'dns-in',
			action: 'hijack-dns'
		}
	],
	rule_set: [],
	auto_detect_interface: isEmpty(default_interface) ? true : null,
	default_interface: default_interface,
	default_http_client: isEmpty(main_node) ? null : 'main-out'
};

if (match(proxy_mode, /tun/) && !isEmpty(main_node) && needs_neighbor)
	config.route.find_neighbor = true;

if (!isEmpty(main_node)) {
	config.route.default_domain_resolver = {
		action: 'route',
		server: china_dns_enabled ? 'china-dns' : 'default-dns',
		strategy: (ipv6_support !== '1') ? 'prefer_ipv4' : null
	};

	if (length(direct_domain_list))
		push(config.route.rules, {
			rule_set: 'direct-domain',
			action: 'route',
			outbound: 'direct-out'
		});

	if (length(proxy_domain_list))
		push(config.route.rules, {
			rule_set: 'proxy-domain',
			action: 'route',
			outbound: 'main-out'
		});

	if (match(proxy_mode, /tun/)) {
		if (routing_mode === 'bypass_mainland_china')
			push(config.route.rules, { rule_set: 'geoip-cn', action: 'route', outbound: 'direct-out' });
		else if (routing_mode === 'proxy_mainland_china')
			push(config.route.rules, { rule_set: 'geoip-cn', invert: true, action: 'route', outbound: 'direct-out' });
	}

	if (main_udp_node === 'urltest' || dedicated_udp_node)
		push(config.route.rules, {
			network: 'udp',
			action: 'route',
			outbound: 'main-udp-out'
		});
	else if (main_udp_node === 'nil')
		push(config.route.rules, {
			network: 'udp',
			action: 'reject'
		});

	config.route.final = gfwlist_tun ? 'direct-out' : 'main-out';

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

	if (gfwlist_tun)
		push(config.route.rules, {
			rule_set: 'gfw-list',
			action: 'route',
			outbound: 'main-out'
		});

	if (gfwlist_tun)
		push(config.route.rule_set, {
			type: 'remote',
			tag: 'gfw-list',
			format: 'binary',
			url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/gfw.srs'
		});

	if (routing_mode === 'bypass_mainland_china' || (routing_mode === 'proxy_mainland_china' && match(proxy_mode, /tun/))) {
		push(config.route.rule_set, {
			type: 'remote',
			tag: 'geoip-cn',
			format: 'binary',
			url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/cn.srs'
		});
	}

	if (routing_mode === 'bypass_mainland_china') {
		push(config.route.rule_set, {
			type: 'remote',
			tag: 'geosite-cn',
			format: 'binary',
			url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/cn.srs'
		});
		push(config.route.rule_set, {
			type: 'remote',
			tag: 'geosite-noncn',
			format: 'binary',
			url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/geolocation-!cn.srs'
		});
	}
}

let has_remote_ruleset = false;
for (let rs in (config.route.rule_set || []))
	if (rs.type === 'remote')
		has_remote_ruleset = true;

if (isEmpty(config.route.rule_set))
	config.route.rule_set = null;

if (has_remote_ruleset) {
	config.experimental = {
		cache_file: {
			enabled: true,
			path: HP_DIR + '/cache/cache.db',
			store_dns: true
		}
	};
}

if (main_node === 'urltest' || main_udp_node === 'urltest') {
	if (!config.experimental)
		config.experimental = {};
	config.experimental.clash_api = {
		external_controller: `127.0.0.1:${dashboard_port + 1}`
	};
}

if (dashboard_enabled)
	config.services = [
		{
			type: 'api',
			tag: 'api-dashboard',
			listen: '::',
			listen_port: dashboard_port,
			secret: dashboard_secret,
			dashboard: {
				enabled: true,
				path: dashboard_path
			}
		}
	];

system('mkdir -p ' + RUN_DIR);
atomicWrite(RUN_DIR + '/sing-box-c.json', sprintf('%.J\n', removeBlankAttrs(config)));
