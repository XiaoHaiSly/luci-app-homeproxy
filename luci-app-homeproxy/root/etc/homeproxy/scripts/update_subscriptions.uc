#!/usr/bin/ucode
/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2023 ImmortalWrt.org
 */

'use strict';

import { md5 } from 'digest';
import { open } from 'fs';
import { connect } from 'ubus';
import { cursor } from 'uci';

import { urldecode, urlencode } from 'luci.http';

import {
	wGET, decodeBase64Str, getTime, isEmpty, parseURL,
	reconcileUrltestNodes, validation, HP_DIR, RUN_DIR
} from 'homeproxy';

/* UCI config start */
const uci = cursor();

const uciconfig = 'homeproxy';
uci.load(uciconfig);

const ucimain = 'config',
      ucinode = 'node',
      ucisubscription = 'subscription';

const allow_insecure = uci.get(uciconfig, ucisubscription, 'allow_insecure') || '0',
      filter_mode = uci.get(uciconfig, ucisubscription, 'filter_nodes') || 'disabled',
      filter_keywords = uci.get(uciconfig, ucisubscription, 'filter_keywords') || [],
      packet_encoding = uci.get(uciconfig, ucisubscription, 'packet_encoding') || 'xudp',
      subscription_urls = uci.get(uciconfig, ucisubscription, 'subscription_url') || [],
      user_agent = uci.get(uciconfig, ucisubscription, 'user_agent'),
      via_proxy = uci.get(uciconfig, ucisubscription, 'update_via_proxy') || '0';

/* UCI config end */

/* String helper start */
function filter_check(name) {
	if (isEmpty(name) || filter_mode === 'disabled' || isEmpty(filter_keywords))
		return false;

	let ret = false;
	for (let i in filter_keywords) {
		const patten = regexp(i);
		if (match(name, patten))
			ret = true;
	}
	if (filter_mode === 'whitelist')
		ret = !ret;

	return ret;
}
/* String helper end */

/* Common var start */
const node_cache = {},
      node_result = [];

const ubus = connect();
const core_features = ubus.call('luci.homeproxy', 'core_get_features', {}) || {};
/* Common var end */

/* Log */
system(`mkdir -p ${RUN_DIR}`);
function log(...args) {
	const logfile = open(`${RUN_DIR}/homeproxy.log`, 'a');
	logfile.write(`${getTime()} [SUBSCRIBE] ${join(' ', args)}\n`);
	logfile.close();
}

function service_action(action) {
	return system([ '/etc/init.d/homeproxy', action ]);
}

/* Map an XHTTP xmux object onto the xhttp_xmux_* UCI options */
function apply_xmux(config, prefix, xmux) {
	if (!xmux)
		return;

	config[`${prefix}_max_concurrency`] = xmux.maxConcurrency || null;
	config[`${prefix}_max_connections`] = xmux.maxConnections || null;
	config[`${prefix}_c_max_reuse_times`] = xmux.cMaxReuseTimes || null;
	config[`${prefix}_h_max_request_times`] = xmux.hMaxRequestTimes || null;
	config[`${prefix}_h_max_reusable_secs`] = xmux.hMaxReusableSecs || null;
	config[`${prefix}_h_keep_alive_period`] = xmux.hKeepAlivePeriod || null;
}

function parse_uri(uri) {
	let config, url, params;

	if (type(uri) === 'object') {
		if (uri.nodetype === 'sip008') {
			/* https://shadowsocks.org/guide/sip008.html */
			config = {
				label: uri.remarks,
				type: 'shadowsocks',
				address: uri.server,
				port: uri.server_port,
				shadowsocks_encrypt_method: uri.method,
				password: uri.password,
				shadowsocks_plugin: uri.plugin,
				shadowsocks_plugin_opts: uri.plugin_opts
			};
		}
	} else if (type(uri) === 'string') {
		uri = split(trim(uri), '://');

		switch (uri[0]) {
		case 'anytls':
			/* https://github.com/anytls/anytls-go/blob/v0.0.8/docs/uri_scheme.md */
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams || {};

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'anytls',
				address: url.hostname,
				port: url.port,
				password: urldecode(url.username),
				tls: '1',
				tls_sni: params.sni,
				tls_insecure: (params.insecure === '1') ? '1' : '0'
			};

			break;
		case 'http':
		case 'https':
			url = parseURL('http://' + uri[1]) || {};

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'http',
				address: url.hostname,
				port: url.port,
				username: url.username ? urldecode(url.username) : null,
				password: url.password ? urldecode(url.password) : null,
				tls: (uri[0] === 'https') ? '1' : '0'
			};

			break;
		case 'hysteria':
			/* https://github.com/HyNetwork/hysteria/wiki/URI-Scheme */
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams || {};

			if (!core_features.with_quic || (params.protocol && params.protocol !== 'udp')) {
				log(sprintf('Skipping unsupported %s node: %s.', uri[0], urldecode(url.hash) || url.hostname));
				if (!core_features.with_quic)
					log(sprintf('Please rebuild hiddify-core with %s support!', 'QUIC'));

				return null;
			}

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'hysteria',
				address: url.hostname,
				port: url.port,
				hysteria_auth_type: params.auth ? 'string' : null,
				hysteria_auth_payload: params.auth,
				hysteria_obfs_password: params.obfsParam,
				hysteria_down_mbps: params.downmbps,
				hysteria_up_mbps: params.upmbps,
				tls: '1',
				tls_insecure: (params.insecure in ['true', '1']) ? '1' : '0',
				tls_sni: params.peer,
				tls_alpn: params.alpn
			};

			break;
		case 'hysteria2':
		case 'hy2':
			/* https://v2.hysteria.network/docs/developers/URI-Scheme/ */
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams || {};

			if (!core_features.with_quic) {
				log(sprintf('Skipping unsupported %s node: %s.', uri[0], urldecode(url.hash) || url.hostname));
				log(sprintf('Please rebuild hiddify-core with %s support!', 'QUIC'));
				return null;
			}

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'hysteria2',
				address: url.hostname,
				port: url.port,
				password: url.username ? (
					urldecode(url.username + (url.password ? (':' + url.password) : ''))
				) : null,
				hysteria_obfs_type: params.obfs,
				hysteria_obfs_password: params['obfs-password'],
				tls: '1',
				tls_insecure: (params.insecure === '1') ? '1' : '0',
				tls_sni: params.sni
			};

			break;
		case 'socks':
		case 'socks4':
		case 'socks4a':
		case 'socks5':
		case 'socks5h':
			url = parseURL('http://' + uri[1]) || {};

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'socks',
				address: url.hostname,
				port: url.port,
				username: url.username ? urldecode(url.username) : null,
				password: url.password ? urldecode(url.password) : null,
				socks_version: (match(uri[0], /4/)) ? '4' : '5'
			};

			break;
		case 'ss':
			/* "Lovely" Shadowrocket format */
			const ss_suri = split(uri[1], '#');
			let ss_slabel = '';
			if (length(ss_suri) <= 2) {
				if (length(ss_suri) === 2)
					ss_slabel = '#' + ss_suri[1];
				if (decodeBase64Str(ss_suri[0]))
					uri[1] = decodeBase64Str(ss_suri[0]) + ss_slabel;
			}

			/* Legacy format is not supported, it should be never appeared in modern subscriptions */
			/* https://github.com/shadowsocks/shadowsocks-org/commit/78ca46cd6859a4e9475953ed34a2d301454f579e */

			/* SIP002 format https://shadowsocks.org/guide/sip002.html */
			url = parseURL('http://' + uri[1]) || {};

			let ss_userinfo = {};
			if (url.username && url.password)
				/* User info encoded with URIComponent */
				ss_userinfo = [url.username, urldecode(url.password)];
			else if (url.username)
				/* User info encoded with base64 */
				ss_userinfo = split(decodeBase64Str(urldecode(url.username)), ':', 2);

			let ss_plugin, ss_plugin_opts;
			if (url.search && url.searchParams.plugin) {
				const ss_plugin_info = split(url.searchParams.plugin, ';', 2);
				ss_plugin = ss_plugin_info[0];
				if (ss_plugin === 'simple-obfs')
					/* Fix non-standard plugin name */
					ss_plugin = 'obfs-local';
				ss_plugin_opts = ss_plugin_info[1];
			}

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'shadowsocks',
				address: url.hostname,
				port: url.port,
				shadowsocks_encrypt_method: ss_userinfo[0],
				password: ss_userinfo[1],
				shadowsocks_plugin: ss_plugin,
				shadowsocks_plugin_opts: ss_plugin_opts
			};

			break;
		case 'trojan':
			/* https://p4gefau1t.github.io/trojan-go/developer/url/ */
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams || {};

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'trojan',
				address: url.hostname,
				port: url.port,
				password: urldecode(url.username),
				transport: (params.type !== 'tcp') ? params.type : null,
				tls: '1',
				tls_sni: params.sni
			};
			switch(params.type) {
			case 'grpc':
				config.grpc_servicename = params.serviceName;
				break;
			case 'ws':
				config.ws_host = params.host ? urldecode(params.host) : null;
				config.ws_path = params.path ? urldecode(params.path) : null;
				if (config.ws_path && match(config.ws_path, /\?ed=/)) {
					config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
					config.websocket_early_data = split(config.ws_path, '?ed=')[1];
					config.ws_path = split(config.ws_path, '?ed=')[0];
				}
				break;
			}

			break;
		case 'tuic':
			/* https://github.com/daeuniverse/dae/discussions/182 */
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams || {};

			if (!core_features.with_quic) {
				log(sprintf('Skipping unsupported %s node: %s.', uri[0], urldecode(url.hash) || url.hostname));
				log(sprintf('Please rebuild hiddify-core with %s support!', 'QUIC'));

				return null;
			}

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'tuic',
				address: url.hostname,
				port: url.port,
				uuid: url.username,
				password: url.password ? urldecode(url.password) : null,
				tuic_congestion_control: params.congestion_control,
				tuic_udp_relay_mode: params.udp_relay_mode,
				tls: '1',
				tls_sni: params.sni,
				tls_alpn: params.alpn ? split(urldecode(params.alpn), ',') : null,
			};

			break;
		case 'vless':
			/* https://github.com/XTLS/Xray-core/discussions/716 */
			url = parseURL('http://' + uri[1]) || {};
			params = url.searchParams || {};

			/* Unsupported protocol */
			if (params.type === 'kcp') {
				log(sprintf('Skipping sunsupported %s node: %s.', uri[0], urldecode(url.hash) || url.hostname));
				return null;
			} else if (params.type === 'quic' && ((params.quicSecurity && params.quicSecurity !== 'none') || !core_features.with_quic)) {
				log(sprintf('Skipping sunsupported %s node: %s.', uri[0], urldecode(url.hash) || url.hostname));
				if (!core_features.with_quic)
					log(sprintf('Please rebuild hiddify-core with %s support!', 'QUIC'));

				return null;
			}

			config = {
				label: url.hash ? urldecode(url.hash) : null,
				type: 'vless',
				address: url.hostname,
				port: url.port,
				uuid: url.username,
				transport: (params.type !== 'tcp') ? params.type : null,
				tls: (params.security in ['tls', 'xtls', 'reality']) ? '1' : '0',
				tls_sni: params.sni,
				tls_alpn: params.alpn ? split(urldecode(params.alpn), ',') : null,
				tls_reality: (params.security === 'reality') ? '1' : '0',
				tls_reality_public_key: params.pbk ? urldecode(params.pbk) : null,
				tls_reality_short_id: params.sid,
				tls_utls: core_features.with_utls ? params.fp : null,
				vless_flow: (params.security in ['tls', 'reality']) ? params.flow : null,
				vless_encryption: params.encryption || null
			};
			switch(params.type) {
			case 'grpc':
				config.grpc_servicename = params.serviceName;
				break;
			case 'http':
			case 'tcp':
				if (params.type === 'http' || params.headerType === 'http') {
					config.http_host = params.host ? split(urldecode(params.host), ',') : null;
					config.http_path = params.path ? urldecode(params.path) : null;
				}
				break;
			case 'httpupgrade':
				config.httpupgrade_host = params.host ? urldecode(params.host) : null;
				config.http_path = params.path ? urldecode(params.path) : null;
				break;
			case 'ws':
				config.ws_host = params.host ? urldecode(params.host) : null;
				config.ws_path = params.path ? urldecode(params.path) : null;
				if (config.ws_path && match(config.ws_path, /\?ed=/)) {
					config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
					config.websocket_early_data = split(config.ws_path, '?ed=')[1];
					config.ws_path = split(config.ws_path, '?ed=')[0];
				}
				break;
			case 'xhttp':
			case 'splithttp':
				config.transport = 'xhttp';
				config.xhttp_host = params.host ? urldecode(params.host) : null;
				config.xhttp_path = params.path ? urldecode(params.path) : null;
				config.xhttp_mode = params.mode || null;

				let xhttp_extra = {};
				if (params.extra) {
					try {
						xhttp_extra = json(urldecode(params.extra)) || {};
					} catch (e) {
						xhttp_extra = {};
					}
				}

				config.xhttp_method = xhttp_extra.uplinkHTTPMethod || xhttp_extra.method || params.method || null;
				config.xhttp_domain_strategy = xhttp_extra.domainStrategy || params.domainStrategy || null;
				if (xhttp_extra.headers) {
					config.xhttp_headers = [];
					for (let k, v in xhttp_extra.headers)
						push(config.xhttp_headers, sprintf('%s: %s', k, v));
				}

				config.xhttp_padding_bytes = xhttp_extra.xPaddingBytes || params.paddingBytes || null;
				config.xhttp_no_grpc_header = (xhttp_extra.noGRPCHeader === true || params.noGRPCHeader === '1') ? '1' : null;
				config.xhttp_sc_max_each_post_bytes = xhttp_extra.scMaxEachPostBytes || params.scMaxEachPostBytes || null;
				config.xhttp_sc_min_posts_interval_ms = xhttp_extra.scMinPostsIntervalMs || params.scMinPostsIntervalMs || null;
				config.xhttp_sc_max_buffered_posts = xhttp_extra.scMaxBufferedPosts || null;
				config.xhttp_sc_stream_up_server_secs = xhttp_extra.scStreamUpServerSecs || null;
				config.xhttp_no_sse_header = (xhttp_extra.noSSEHeader === true) ? '1' : null;

				config.xhttp_x_padding_obfs_mode = (xhttp_extra.xPaddingObfsMode === true) ? '1' : null;
				config.xhttp_x_padding_placement = xhttp_extra.xPaddingPlacement || null;
				config.xhttp_x_padding_key = xhttp_extra.xPaddingKey || null;
				config.xhttp_x_padding_header = xhttp_extra.xPaddingHeader || null;
				config.xhttp_x_padding_method = xhttp_extra.xPaddingMethod || null;

				config.xhttp_session_placement = xhttp_extra.sessionPlacement || null;
				config.xhttp_session_key = xhttp_extra.sessionKey || null;

				config.xhttp_seq_placement = xhttp_extra.seqPlacement || null;
				config.xhttp_seq_key = xhttp_extra.seqKey || null;

				config.xhttp_uplink_data_placement = xhttp_extra.uplinkDataPlacement || null;
				config.xhttp_uplink_data_key = xhttp_extra.uplinkDataKey || null;
				config.xhttp_uplink_chunk_size = xhttp_extra.uplinkChunkSize || null;

				if (xhttp_extra.downloadSettings || xhttp_extra.download) {
					let dl = xhttp_extra.downloadSettings || xhttp_extra.download;
					config.xhttp_download_host = dl.host || null;
					config.xhttp_download_path = dl.path || null;
					config.xhttp_download_server = dl.address || dl.server || null;
					config.xhttp_download_server_port = dl.port || dl.server_port || null;
					config.xhttp_download_domain_strategy = dl.domainStrategy || null;
					config.xhttp_download_padding_bytes = dl.xPaddingBytes || null;
					config.xhttp_download_method = dl.uplinkHTTPMethod || dl.method || null;
					config.xhttp_download_no_grpc_header = (dl.noGRPCHeader === true) ? '1' : null;
					config.xhttp_download_no_sse_header = (dl.noSSEHeader === true) ? '1' : null;
					config.xhttp_download_sc_max_each_post_bytes = dl.scMaxEachPostBytes || null;
					config.xhttp_download_sc_min_posts_interval_ms = dl.scMinPostsIntervalMs || null;
					config.xhttp_download_sc_max_buffered_posts = dl.scMaxBufferedPosts || null;
					config.xhttp_download_sc_stream_up_server_secs = dl.scStreamUpServerSecs || null;
					if (dl.tlsSettings || dl.security === 'tls') {
						config.xhttp_download_tls = '1';
						config.xhttp_download_tls_server_name = dl.tlsSettings?.serverName || null;
						const dl_alpn = dl.tlsSettings?.alpn;
						config.xhttp_download_tls_alpn = isEmpty(dl_alpn) ? null :
							((type(dl_alpn) === 'array') ? dl_alpn : split(dl_alpn, ','));
						config.xhttp_download_tls_insecure =
							(dl.tlsSettings?.allowInsecure === true || dl.tlsSettings?.insecure === true) ? '1' : null;
					}
					if (dl.headers) {
						config.xhttp_download_headers = [];
						for (let k, v in dl.headers)
							push(config.xhttp_download_headers, sprintf('%s: %s', k, v));
					}
					config.xhttp_download_x_padding_obfs_mode = (dl.xPaddingObfsMode === true) ? '1' : null;
					config.xhttp_download_x_padding_placement = dl.xPaddingPlacement || null;
					config.xhttp_download_x_padding_key = dl.xPaddingKey || null;
					config.xhttp_download_x_padding_header = dl.xPaddingHeader || null;
					config.xhttp_download_x_padding_method = dl.xPaddingMethod || null;
					config.xhttp_download_session_placement = dl.sessionPlacement || null;
					config.xhttp_download_session_key = dl.sessionKey || null;
					config.xhttp_download_seq_placement = dl.seqPlacement || null;
					config.xhttp_download_seq_key = dl.seqKey || null;
					config.xhttp_download_uplink_data_placement = dl.uplinkDataPlacement || null;
					config.xhttp_download_uplink_data_key = dl.uplinkDataKey || null;
					config.xhttp_download_uplink_chunk_size = dl.uplinkChunkSize || null;
					if (dl.xmux)
						apply_xmux(config, 'xhttp_download_xmux', dl.xmux);
				}

				if (xhttp_extra.xmux)
					apply_xmux(config, 'xhttp_xmux', xhttp_extra.xmux);

				break;
			}

			break;
		case 'vmess':
			/* "Lovely" shadowrocket format */
			if (match(uri, /&/)) {
				log(sprintf('Skipping unsupported %s format.', uri[0]));
				return null;
			}

			/* https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link */
			try {
				uri = json(decodeBase64Str(uri[1])) || {};
			} catch(e) {
				log(sprintf('Skipping unsupported %s format.', uri[0]));
				return null;
			}

			if (uri.v != '2') {
				log(sprintf('Skipping unsupported %s format.', uri[0]));
				return null;
			/* Unsupported protocol */
			} else if (uri.net === 'kcp') {
				log(sprintf('Skipping unsupported %s node: %s.', uri[0], uri.ps || uri.add));
				return null;
			} else if (uri.net === 'quic' && ((uri.type && uri.type !== 'none') || uri.path || !core_features.with_quic)) {
				log(sprintf('Skipping unsupported %s node: %s.', uri[0], uri.ps || uri.add));
				if (!core_features.with_quic)
					log(sprintf('Please rebuild hiddify-core with %s support!', 'QUIC'));

				return null;
			}
			/*
			 * https://www.v2fly.org/config/protocols/vmess.html#vmess-md5-%E8%AE%A4%E8%AF%81%E4%BF%A1%E6%81%AF-%E6%B7%98%E6%B1%B0%E6%9C%BA%E5%88%B6
			 * else if (uri.aid && int(uri.aid) !== 0) {
			 * 	log(sprintf('Skipping unsupported %s node: %s.', uri[0], uri.ps || uri.add));
			 * 	return null;
			 * }
			 */

			config = {
				label: uri.ps ? urldecode(uri.ps) : null,
				type: 'vmess',
				address: uri.add,
				port: uri.port,
				uuid: uri.id,
				vmess_alterid: uri.aid,
				vmess_encrypt: uri.scy || 'auto',
				vmess_global_padding: '1',
				transport: (uri.net !== 'tcp') ? uri.net : null,
				tls: (uri.tls === 'tls') ? '1' : '0',
				tls_sni: uri.sni || uri.host,
				tls_alpn: uri.alpn ? split(uri.alpn, ',') : null,
				tls_utls: core_features.with_utls ? uri.fp : null
			};
			switch (uri.net) {
			case 'grpc':
				config.grpc_servicename = uri.path;
				break;
			case 'h2':
			case 'tcp':
				if (uri.net === 'h2' || uri.type === 'http') {
					config.transport = 'http';
					config.http_host = uri.host ? split(uri.host, ',') : null;
					config.http_path = uri.path;
				}
				break;
			case 'httpupgrade':
				config.httpupgrade_host = uri.host;
				config.http_path = uri.path;
				break;
			case 'ws':
				config.ws_host = uri.host;
				config.ws_path = uri.path;
				if (config.ws_path && match(config.ws_path, /\?ed=/)) {
					config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
					config.websocket_early_data = split(config.ws_path, '?ed=')[1];
					config.ws_path = split(config.ws_path, '?ed=')[0];
				}
				break;
			}

			break;
		}
	}

	if (!isEmpty(config)) {
		/* Anti-DPI TLS options, not covered by the standard share link format */
		if (config.tls === '1' && params) {
			if (params.fragment === '1' || params.fragment === 'true')
				config.tls_fragment = '1';
			config.tls_fragment_fallback_delay = params.fragmentFallbackDelay || null;
			if (params.recordFragment === '1' || params.recordFragment === 'true')
				config.tls_record_fragment = '1';
			config.tls_spoof = params.spoof ? urldecode(params.spoof) : null;
			config.tls_spoof_method = params.spoofMethod || null;
		}

		if (config.address)
			config.address = replace(config.address, /\[|\]/g, '');

		if (!validation('host', config.address) || !validation('port', config.port)) {
			log(sprintf('Skipping invalid %s node: %s.', config.type, config.label || 'NULL'));
			return null;
		} else if (!config.label)
			config.label = (validation('ip6addr', config.address) ?
				`[${config.address}]` : config.address) + ':' + config.port;
	}

	return config;
}

function main() {
	if (via_proxy !== '1') {
		log('Stopping service...');
		service_action('stop');
	}

	for (let url in subscription_urls) {
		url = replace(url, /#.*$/, '');
		const groupHash = md5(url);
		node_cache[groupHash] = {};

		const res = wGET(url, user_agent);
		if (isEmpty(res)) {
			log(sprintf('Failed to fetch resources from %s.', url));
			continue;
		}

		let nodes;
		try {
			nodes = json(res).servers || json(res);

			/* Shadowsocks SIP008 format */
			if (nodes[0].server && nodes[0].method)
				map(nodes, (_, i) => nodes[i].nodetype = 'sip008');
		} catch(e) {
			nodes = decodeBase64Str(res);
			nodes = nodes ? split(trim(replace(nodes, / /g, '_')), '\n') : [];
		}

		let count = 0;
		for (let node in nodes) {
			let config;
			if (!isEmpty(node))
				config = parse_uri(node);
			if (isEmpty(config))
				continue;

			const label = config.label;
			config.label = null;
			const confHash = md5(sprintf('%J', config)),
			      nameHash = md5(label);
			config.label = label;

			if (filter_check(config.label))
				log(sprintf('Skipping blacklist node: %s.', config.label));
			else if (node_cache[groupHash][confHash] || node_cache[groupHash][nameHash])
				log(sprintf('Skipping duplicate node: %s.', config.label));
			else {
				if (config.tls === '1' && allow_insecure === '1')
					config.tls_insecure = '1';
				if (config.type in ['vless', 'vmess'])
					config.packet_encoding = packet_encoding;

				config.grouphash = groupHash;
				push(node_result, []);
				push(node_result[length(node_result)-1], config);
				node_cache[groupHash][confHash] = config;
				node_cache[groupHash][nameHash] = config;

				count++;
			}
		}

		if (count == 0)
			log(sprintf('No valid node found in %s.', url));
		else
			log(sprintf('Successfully fetched %s nodes of total %s from %s.', count, length(nodes), url));
	}

	if (isEmpty(node_result)) {
		log('Failed to update subscriptions: no valid node found.');

		if (via_proxy !== '1') {
			log('Starting service...');
			service_action('start');
		}

		return false;
	}

	let added = 0, removed = 0;
	uci.foreach(uciconfig, ucinode, (cfg) => {
		/* Nodes created by the user */
		if (!cfg.grouphash)
			return null;

		/* Empty object - failed to fetch nodes */
		if (length(node_cache[cfg.grouphash]) === 0)
			return null;

		if (!node_cache[cfg.grouphash] || !node_cache[cfg.grouphash][cfg['.name']]) {
			uci.delete(uciconfig, cfg['.name']);
			removed++;

			log(sprintf('Removing node: %s.', cfg.label || cfg['name']));
		} else {
			map(keys(cfg), (v) => {
				if (v in node_cache[cfg.grouphash][cfg['.name']])
					uci.set(uciconfig, cfg['.name'], v, node_cache[cfg.grouphash][cfg['.name']][v]);
				else
					uci.delete(uciconfig, cfg['.name'], v);
			});
			node_cache[cfg.grouphash][cfg['.name']].isExisting = true;
		}
	});
	for (let nodes in node_result)
		map(nodes, (node) => {
			if (node.isExisting)
				return null;

			const nameHash = md5(node.label);
			uci.set(uciconfig, nameHash, 'node');
			map(keys(node), (v) => uci.set(uciconfig, nameHash, v, node[v]));

			added++;
			log(sprintf('Adding node: %s.', node.label));
		});
	uci.commit(uciconfig);

	let need_restart = (via_proxy !== '1');

	/* Drop references to nodes that disappeared with this update: the URLTest
	   lists of the main node and of the routing rules, and stale main nodes. */
	const reconcile = reconcileUrltestNodes(uci, uciconfig, log);

	if (reconcile.changed) {
		uci.commit(uciconfig);
		need_restart = true;
	}

	if (need_restart) {
		log('Restarting service...');
		service_action('stop');
		service_action('start');
	}

	log(sprintf('%s nodes added, %s removed.', added, removed));
	log('Successfully updated subscriptions.');
}

if (!isEmpty(subscription_urls))
	try {
		call(main);
	} catch(e) {
		log('[FATAL ERROR] An error occurred during updating subscriptions:');
		log(sprintf('%s: %s', e.type, e.message));
		log(e.stacktrace[0].context);

		log('Restarting service...');
		service_action('stop');
		service_action('start');
	}
