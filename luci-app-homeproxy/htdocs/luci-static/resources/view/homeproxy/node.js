/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2022-2025 ImmortalWrt.org
 */

'use strict';
'require form';
'require fs';
'require uci';
'require ui';
'require view';

'require homeproxy as hp';
'require tools.widgets as widgets';

function allowInsecureConfirm(ev, _section_id, value) {
	if (value === '1' && !confirm(_('Are you sure to allow insecure?')))
		ev.target.firstElementChild.checked = null;
}

function parseShareLink(uri, features) {
	let config, url, params;

	uri = uri.split('://');
	if (uri[0] && uri[1]) {
		switch (uri[0]) {
		case 'anytls':
			/* https://github.com/anytls/anytls-go/blob/v0.0.8/docs/uri_scheme.md */
			url = new URL('http://' + uri[1]);
			params = url.searchParams;

			/* Check if password exists */
			if (!url.username)
				return null;

			config = {
				label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
				type: 'anytls',
				address: url.hostname,
				port: url.port || '80',
				password: url.username ? decodeURIComponent(url.username) : null,
				tls: '1',
				tls_sni: params.get('sni'),
				tls_insecure: (params.get('insecure') === '1') ? '1' : '0'
			};

			break;
		case 'http':
		case 'https':
			url = new URL('http://' + uri[1]);

			config = {
				label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
				type: 'http',
				address: url.hostname,
				port: url.port || '80',
				username: url.username ? decodeURIComponent(url.username) : null,
				password: url.password ? decodeURIComponent(url.password) : null,
				tls: (uri[0] === 'https') ? '1' : '0'
			};

			break;
		case 'hysteria':
			/* https://github.com/HyNetwork/hysteria/wiki/URI-Scheme */
			url = new URL('http://' + uri[1]);
			params = url.searchParams;

			/* WeChat-Video / FakeTCP are unsupported by sing-box currently */
			if (!features.with_quic || (params.get('protocol') && params.get('protocol') !== 'udp'))
				return null;

			config = {
				label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
				type: 'hysteria',
				address: url.hostname,
				port: url.port || '80',
				hysteria_protocol: params.get('protocol') || 'udp',
				hysteria_auth_type: params.get('auth') ? 'string' : null,
				hysteria_auth_payload: params.get('auth'),
				hysteria_obfs_password: params.get('obfsParam'),
				hysteria_down_mbps: params.get('downmbps'),
				hysteria_up_mbps: params.get('upmbps'),
				tls: '1',
				tls_sni: params.get('peer'),
				tls_alpn: params.get('alpn'),
				tls_insecure: (params.get('insecure') === '1') ? '1' : '0'
			};

			break;
		case 'hysteria2':
		case 'hy2':
			/* https://v2.hysteria.network/docs/developers/URI-Scheme/ */
			url = new URL('http://' + uri[1]);
			params = url.searchParams;

			if (!features.with_quic)
				return null;

			config = {
				label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
				type: 'hysteria2',
				address: url.hostname,
				port: url.port || '80',
				password: url.username ? (
					decodeURIComponent(url.username + (url.password ? (':' + url.password) : ''))
				) : null,
				hysteria_obfs_type: params.get('obfs'),
				hysteria_obfs_password: params.get('obfs-password'),
				tls: '1',
				tls_sni: params.get('sni'),
				tls_insecure: params.get('insecure') ? '1' : '0'
			};

			break;
		case 'socks':
		case 'socks4':
		case 'socks4a':
		case 'socks5':
		case 'socks5h':
			url = new URL('http://' + uri[1]);

			config = {
				label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
				type: 'socks',
				address: url.hostname,
				port: url.port || '80',
				username: url.username ? decodeURIComponent(url.username) : null,
				password: url.password ? decodeURIComponent(url.password) : null,
				socks_version: (uri[0].includes('4')) ? '4' : '5'
			};

			break;
		case 'ss':
			try {
				/* "Lovely" Shadowrocket format */
				try {
					let suri = uri[1].split('#'), slabel = '';
					if (suri.length <= 2) {
						if (suri.length === 2)
							slabel = '#' + suri[1];
						uri[1] = hp.decodeBase64Str(suri[0]) + slabel;
					}
				} catch(e) { }

				/* SIP002 format https://shadowsocks.org/guide/sip002.html */
				url = new URL('http://' + uri[1]);

				let userinfo;
				if (url.username && url.password) {
					/* User info encoded with URIComponent */
					userinfo = [url.username, decodeURIComponent(url.password)];
				} else if (url.username) {
					/* User info encoded with base64 */
					userinfo = hp.decodeBase64Str(decodeURIComponent(url.username)).split(':');
					if (userinfo.length > 1)
						userinfo = [userinfo[0], userinfo.slice(1).join(':')]
				}

				if (!hp.shadowsocks_encrypt_methods.includes(userinfo[0]))
					return null;

				let plugin, plugin_opts;
				if (url.search && url.searchParams.get('plugin')) {
					let plugin_info = url.searchParams.get('plugin').split(';');
					plugin = plugin_info[0];
					plugin_opts = (plugin_info.length > 1) ? plugin_info.slice(1).join(';') : null;
				}

				config = {
					label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
					type: 'shadowsocks',
					address: url.hostname,
					port: url.port || '80',
					shadowsocks_encrypt_method: userinfo[0],
					password: userinfo[1],
					shadowsocks_plugin: plugin,
					shadowsocks_plugin_opts: plugin_opts
				};
			} catch(e) {
				/* Legacy format https://github.com/shadowsocks/shadowsocks-org/commit/78ca46cd6859a4e9475953ed34a2d301454f579e */
				uri = uri[1].split('@');
				if (uri.length < 2)
					return null;
				else if (uri.length > 2)
					uri = [ uri.slice(0, -1).join('@'), uri.slice(-1).toString() ];

				config = {
					type: 'shadowsocks',
					address: uri[1].split(':')[0],
					port: uri[1].split(':')[1],
					shadowsocks_encrypt_method: uri[0].split(':')[0],
					password: uri[0].split(':').slice(1).join(':')
				};
			}

			break;
		case 'trojan':
			/* https://p4gefau1t.github.io/trojan-go/developer/url/ */
			url = new URL('http://' + uri[1]);
			params = url.searchParams;

			/* Check if password exists */
			if (!url.username)
				return null;

			config = {
				label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
				type: 'trojan',
				address: url.hostname,
				port: url.port || '80',
				password: decodeURIComponent(url.username),
				transport: params.get('type') !== 'tcp' ? params.get('type') : null,
				tls: '1',
				tls_sni: params.get('sni')
			};
			switch (params.get('type')) {
			case 'grpc':
				config.grpc_servicename = params.get('serviceName');
				break;
			case 'ws':
				config.ws_host = params.get('host') ? decodeURIComponent(params.get('host')) : null;
				config.ws_path = params.get('path') ? decodeURIComponent(params.get('path')) : null;
				if (config.ws_path && config.ws_path.includes('?ed=')) {
					config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
					config.websocket_early_data = config.ws_path.split('?ed=')[1];
					config.ws_path = config.ws_path.split('?ed=')[0];
				}
				break;
			}

			break;
		case 'tuic':
			/* https://github.com/daeuniverse/dae/discussions/182 */
			url = new URL('http://' + uri[1]);
			params = url.searchParams;

			/* Check if uuid exists */
			if (!url.username)
				return null;

			config = {
				label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
				type: 'tuic',
				address: url.hostname,
				port: url.port || '80',
				uuid: url.username,
				password: url.password ? decodeURIComponent(url.password) : null,
				tuic_congestion_control: params.get('congestion_control'),
				tuic_udp_relay_mode: params.get('udp_relay_mode'),
				tls: '1',
				tls_sni: params.get('sni'),
				tls_alpn: params.get('alpn') ? decodeURIComponent(params.get('alpn')).split(',') : null
			};

			break;
		case 'vless':
			/* https://github.com/XTLS/Xray-core/discussions/716 */
			url = new URL('http://' + uri[1]);
			params = url.searchParams;

			/* Unsupported protocol */
			if (params.get('type') === 'kcp')
				return null;
			else if (params.get('type') === 'quic' && ((params.get('quicSecurity') && params.get('quicSecurity') !== 'none') || !features.with_quic))
				return null;
			/* Check if uuid and type exist */
			if (!url.username || !params.get('type'))
				return null;

			config = {
				label: url.hash ? decodeURIComponent(url.hash.slice(1)) : null,
				type: 'vless',
				address: url.hostname,
				port: url.port || '80',
				uuid: url.username,
				transport: params.get('type') !== 'tcp' ? params.get('type') : null,
				tls: ['tls', 'xtls', 'reality'].includes(params.get('security')) ? '1' : '0',
				tls_sni: params.get('sni'),
				tls_alpn: params.get('alpn') ? decodeURIComponent(params.get('alpn')).split(',') : null,
				tls_reality: (params.get('security') === 'reality') ? '1' : '0',
				tls_reality_public_key: params.get('pbk') ? decodeURIComponent(params.get('pbk')) : null,
				tls_reality_short_id: params.get('sid'),
				tls_utls: features.with_utls ? params.get('fp') : null,
				vless_flow: ['tls', 'reality'].includes(params.get('security')) ? params.get('flow') : null
			};
			switch (params.get('type')) {
			case 'grpc':
				config.grpc_servicename = params.get('serviceName');
				break;
			case 'http':
			case 'tcp':
				if (config.transport === 'http' || params.get('headerType') === 'http') {
					config.http_host = params.get('host') ? decodeURIComponent(params.get('host')).split(',') : null;
					config.http_path = params.get('path') ? decodeURIComponent(params.get('path')) : null;
				}
				break;
			case 'httpupgrade':
				config.httpupgrade_host = params.get('host') ? decodeURIComponent(params.get('host')) : null;
				config.http_path = params.get('path') ? decodeURIComponent(params.get('path')) : null;
				break;
			case 'ws':
				config.ws_host = params.get('host') ? decodeURIComponent(params.get('host')) : null;
				config.ws_path = params.get('path') ? decodeURIComponent(params.get('path')) : null;
				if (config.ws_path && config.ws_path.includes('?ed=')) {
					config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
					config.websocket_early_data = config.ws_path.split('?ed=')[1];
					config.ws_path = config.ws_path.split('?ed=')[0];
				}
				break;
			case 'xhttp':
			case 'splithttp':
				config.transport = 'xhttp';
				config.xhttp_host = params.get('host') ? decodeURIComponent(params.get('host')) : null;
				config.xhttp_path = params.get('path') ? decodeURIComponent(params.get('path')) : null;
				config.xhttp_mode = params.get('mode') || null;

				let xhttp_extra = {};
				if (params.get('extra')) {
					try {
						xhttp_extra = JSON.parse(decodeURIComponent(params.get('extra'))) || {};
					} catch (e) {
						xhttp_extra = {};
					}
				}

				config.xhttp_method = xhttp_extra.uplinkHTTPMethod || xhttp_extra.method || params.get('method') || null;
				config.xhttp_domain_strategy = xhttp_extra.domainStrategy || params.get('domainStrategy') || null;
				config.xhttp_congestion_controller = xhttp_extra.congestionController || params.get('congestionController') || null;
				config.xhttp_cwnd = xhttp_extra.cwnd || params.get('cwnd') || null;
				if (xhttp_extra.headers) {
					config.xhttp_headers = [];
					for (let k in xhttp_extra.headers)
						config.xhttp_headers.push(k + ': ' + xhttp_extra.headers[k]);
				}

				config.xhttp_padding_bytes = xhttp_extra.xPaddingBytes || params.get('paddingBytes') || null;
				config.xhttp_no_grpc_header = (xhttp_extra.noGRPCHeader === true || params.get('noGRPCHeader') === '1') ? '1' : null;
				config.xhttp_sc_max_each_post_bytes = xhttp_extra.scMaxEachPostBytes || params.get('scMaxEachPostBytes') || null;
				config.xhttp_sc_min_posts_interval_ms = xhttp_extra.scMinPostsIntervalMs || params.get('scMinPostsIntervalMs') || null;
				config.xhttp_sc_max_buffered_posts = xhttp_extra.scMaxBufferedPosts || null;
				config.xhttp_sc_stream_up_server_secs = xhttp_extra.scStreamUpServerSecs || null;
				config.xhttp_server_max_header_bytes = xhttp_extra.serverMaxHeaderBytes || null;
				config.xhttp_no_sse_header = (xhttp_extra.noSSEHeader === true) ? '1' : null;
				if (xhttp_extra.trustedXForwardedFor) {
					config.xhttp_trusted_x_forwarded_for = [];
					for (let v of (Array.isArray(xhttp_extra.trustedXForwardedFor) ? xhttp_extra.trustedXForwardedFor : [xhttp_extra.trustedXForwardedFor]))
						config.xhttp_trusted_x_forwarded_for.push(v);
				}

				config.xhttp_x_padding_obfs_mode = (xhttp_extra.xPaddingObfsMode === true) ? '1' : null;
				config.xhttp_x_padding_placement = xhttp_extra.xPaddingPlacement || null;
				config.xhttp_x_padding_key = xhttp_extra.xPaddingKey || null;
				config.xhttp_x_padding_header = xhttp_extra.xPaddingHeader || null;
				config.xhttp_x_padding_method = xhttp_extra.xPaddingMethod || null;

				config.xhttp_session_placement = xhttp_extra.sessionPlacement || null;
				config.xhttp_session_key = xhttp_extra.sessionKey || null;
				config.xhttp_session_id_table = xhttp_extra.sessionIdTable || null;
				config.xhttp_session_id_length = xhttp_extra.sessionIdLength || null;

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
					config.xhttp_download_congestion_controller = dl.congestionController || null;
					config.xhttp_download_cwnd = dl.cwnd || null;
					config.xhttp_download_no_grpc_header = (dl.noGRPCHeader === true) ? '1' : null;
					config.xhttp_download_no_sse_header = (dl.noSSEHeader === true) ? '1' : null;
					config.xhttp_download_sc_max_each_post_bytes = dl.scMaxEachPostBytes || null;
					config.xhttp_download_sc_min_posts_interval_ms = dl.scMinPostsIntervalMs || null;
					config.xhttp_download_sc_max_buffered_posts = dl.scMaxBufferedPosts || null;
					config.xhttp_download_sc_stream_up_server_secs = dl.scStreamUpServerSecs || null;
					config.xhttp_download_server_max_header_bytes = dl.serverMaxHeaderBytes || null;
					config.xhttp_download_session_id_table = dl.sessionIdTable || null;
					config.xhttp_download_session_id_length = dl.sessionIdLength || null;
					if (dl.trustedXForwardedFor) {
						config.xhttp_download_trusted_x_forwarded_for = [];
						for (let v of (Array.isArray(dl.trustedXForwardedFor) ? dl.trustedXForwardedFor : [dl.trustedXForwardedFor]))
							config.xhttp_download_trusted_x_forwarded_for.push(v);
					}
					if (dl.tlsSettings || dl.security === 'tls') {
						config.xhttp_download_tls = '1';
						config.xhttp_download_tls_server_name = (dl.tlsSettings && dl.tlsSettings.serverName) || null;
						const dlAlpn = dl.tlsSettings && dl.tlsSettings.alpn;
						config.xhttp_download_tls_alpn = !dlAlpn ? null :
							(Array.isArray(dlAlpn) ? dlAlpn : String(dlAlpn).split(','));
						config.xhttp_download_tls_insecure =
							(dl.tlsSettings && (dl.tlsSettings.allowInsecure === true || dl.tlsSettings.insecure === true)) ? '1' : null;
					}
					if (dl.headers) {
						config.xhttp_download_headers = [];
						for (let k in dl.headers)
							config.xhttp_download_headers.push(k + ': ' + dl.headers[k]);
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
					if (dl.xmux) {
						config.xhttp_download_xmux_max_concurrency = dl.xmux.maxConcurrency || null;
						config.xhttp_download_xmux_max_connections = dl.xmux.maxConnections || null;
						config.xhttp_download_xmux_c_max_reuse_times = dl.xmux.cMaxReuseTimes || null;
						config.xhttp_download_xmux_h_max_request_times = dl.xmux.hMaxRequestTimes || null;
						config.xhttp_download_xmux_h_max_reusable_secs = dl.xmux.hMaxReusableSecs || null;
						config.xhttp_download_xmux_h_keep_alive_period = dl.xmux.hKeepAlivePeriod || null;
					}
				}

				if (xhttp_extra.xmux) {
					config.xhttp_xmux_max_concurrency = xhttp_extra.xmux.maxConcurrency || null;
					config.xhttp_xmux_max_connections = xhttp_extra.xmux.maxConnections || null;
					config.xhttp_xmux_c_max_reuse_times = xhttp_extra.xmux.cMaxReuseTimes || null;
					config.xhttp_xmux_h_max_request_times = xhttp_extra.xmux.hMaxRequestTimes || null;
					config.xhttp_xmux_h_max_reusable_secs = xhttp_extra.xmux.hMaxReusableSecs || null;
					config.xhttp_xmux_h_keep_alive_period = xhttp_extra.xmux.hKeepAlivePeriod || null;
				}

				break;
			}

			break;
		case 'vmess':
			/* "Lovely" shadowrocket format */
			if (uri.includes('&'))
				return null;

			/* https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link */
			uri = JSON.parse(hp.decodeBase64Str(uri[1]));

			if (uri.v != '2')
				return null;
			/* Unsupported protocols */
			else if (uri.net === 'kcp')
				return null;
			else if (uri.net === 'quic' && ((uri.type && uri.type !== 'none') || !features.with_quic))
				return null;
			/* https://www.v2fly.org/config/protocols/vmess.html#vmess-md5-%E8%AE%A4%E8%AF%81%E4%BF%A1%E6%81%AF-%E6%B7%98%E6%B1%B0%E6%9C%BA%E5%88%B6
			 * else if (uri.aid && parseInt(uri.aid) !== 0)
			 * 	return null;
			 */

			config = {
				label: uri.ps,
				type: 'vmess',
				address: uri.add,
				port: uri.port,
				uuid: uri.id,
				vmess_alterid: uri.aid,
				vmess_encrypt: uri.scy || 'auto',
				transport: (uri.net !== 'tcp') ? uri.net : null,
				tls: uri.tls === 'tls' ? '1' : '0',
				tls_sni: uri.sni || uri.host,
				tls_alpn: uri.alpn ? uri.alpn.split(',') : null,
				tls_utls: features.with_utls ? uri.fp : null
			};
			switch (uri.net) {
			case 'grpc':
				config.grpc_servicename = uri.path;
				break;
			case 'h2':
			case 'tcp':
				if (uri.net === 'h2' || uri.type === 'http') {
					config.transport = 'http';
					config.http_host = uri.host ? uri.host.split(',') : null;
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
				if (config.ws_path && config.ws_path.includes('?ed=')) {
					config.websocket_early_data_header = 'Sec-WebSocket-Protocol';
					config.websocket_early_data = config.ws_path.split('?ed=')[1];
					config.ws_path = config.ws_path.split('?ed=')[0];
				}
				break;
			}

			break;
		}
	}

	if (config) {
		if (!config.address || !config.port)
			return null;
		else if (!config.label)
			config.label = config.address + ':' + config.port;

		config.address = config.address.replace(/\[|\]/g, '');
	}

	/* Anti-DPI TLS options, not covered by the standard share link format */
	if (config && config.tls === '1' && params) {
		if (params.get('fragment') === '1' || params.get('fragment') === 'true')
			config.tls_fragment = '1';
		config.tls_fragment_fallback_delay = params.get('fragmentFallbackDelay') || null;
		if (params.get('recordFragment') === '1' || params.get('recordFragment') === 'true')
			config.tls_record_fragment = '1';
		config.tls_spoof = params.get('spoof') ? decodeURIComponent(params.get('spoof')) : null;
		config.tls_spoof_method = params.get('spoofMethod') || null;
	}

	return config;
}

function renderNodeSettings(section, data, features, main_node, routing_mode) {
	let s = section, o;
	s.rowcolors = true;
	s.sortable = true;
	s.nodescriptions = true;
	s.modaltitle = L.bind(hp.loadModalTitle, this, _('Node'), _('Add a node'), data[0]);
	s.sectiontitle = L.bind(hp.loadDefaultLabel, this, data[0]);

	if (routing_mode !== 'custom') {
		o = s.option(form.Button, '_apply', _('Apply'));
		o.editable = true;
		o.modalonly = false;
		o.inputstyle = 'apply';
		o.inputtitle = function(section_id) {
			if (main_node == section_id) {
				this.readonly = true;
				return _('Applied');
			} else {
				this.readonly = false;
				return _('Apply');
			}
		}
		o.onclick = function(ev, section_id) {
			uci.set(data[0], 'config', 'main_node', section_id);

			return this.map.save(null, true).then(() => {
				ui.changes.apply(true);
			});
		}
	}

	o = s.option(form.Value, 'label', _('Label'));
	o.load = L.bind(hp.loadDefaultLabel, this, data[0]);
	o.validate = L.bind(hp.validateUniqueValue, this, data[0], 'node', 'label');
	o.modalonly = true;

	o = s.option(form.ListValue, 'type', _('Type'));
	o.value('direct', _('Direct'));
	o.value('anytls', _('AnyTLS'));
	o.value('http', _('HTTP'));
	if (features.with_quic) {
		o.value('hysteria', _('Hysteria'));
		o.value('hysteria2', _('Hysteria2'));
	}
	o.value('shadowsocks', _('Shadowsocks'));
	o.value('shadowtls', _('ShadowTLS'));
	o.value('socks', _('Socks'));
	o.value('ssh', _('SSH'));
	o.value('trojan', _('Trojan'));
	if (features.with_quic)
		o.value('tuic', _('Tuic'));
	if (features.with_wireguard && features.with_gvisor)
		o.value('wireguard', _('WireGuard'));
	o.value('vless', _('VLESS'));
	o.value('vmess', _('VMess'));
	o.rmempty = false;

	o = s.option(form.Value, 'address', _('Address'));
	o.datatype = 'host';
	o.depends({'type': 'direct', '!reverse': true});
	o.rmempty = false;

	o = s.option(form.Value, 'port', _('Port'));
	o.datatype = 'port';
	o.depends({'type': 'direct', '!reverse': true});
	o.rmempty = false;

	o = s.option(form.Value, 'username', _('Username'));
	o.depends('type', 'http');
	o.depends('type', 'socks');
	o.depends('type', 'ssh');
	o.modalonly = true;

	o = s.option(form.Value, 'password', _('Password'));
	o.password = true;
	o.depends('type', 'anytls');
	o.depends('type', 'http');
	o.depends('type', 'hysteria2');
	o.depends('type', 'shadowsocks');
	o.depends('type', 'ssh');
	o.depends('type', 'trojan');
	o.depends('type', 'tuic');
	o.depends({'type': 'shadowtls', 'shadowtls_version': '2'});
	o.depends({'type': 'shadowtls', 'shadowtls_version': '3'});
	o.depends({'type': 'socks', 'socks_version': '5'});
	o.validate = function(section_id, value) {
		if (section_id) {
			let type = this.section.formvalue(section_id, 'type');
			let required_type = [ 'anytls', 'shadowsocks', 'shadowtls', 'trojan' ];

			if (required_type.includes(type)) {
				if (type === 'shadowsocks') {
					let encmode = this.section.formvalue(section_id, 'shadowsocks_encrypt_method');
					if (encmode === 'none')
						return true;
				}
				if (!value)
					return _('Expecting: %s').format(_('non-empty value'));
			}
		}

		return true;
	}
	o.modalonly = true;

	/* Direct config */
	o = s.option(form.ListValue, 'proxy_protocol', _('Proxy protocol'),
		_('Write proxy protocol in the connection header.'));
	o.value('', _('Disable'));
	o.value('1', _('v1'));
	o.value('2', _('v2'));
	o.depends('type', 'direct');
	o.modalonly = true;

	/* AnyTLS config start */
	o = s.option(form.Value, 'anytls_idle_session_check_interval', _('Idle session check interval'),
		_('Interval checking for idle sessions, in seconds.'));
	o.datatype = 'uinteger';
	o.placeholder = '30';
	o.depends('type', 'anytls');
	o.modalonly = true;

	o = s.option(form.Value, 'anytls_idle_session_timeout', _('Idle session check timeout'),
		_('In the check, close sessions that have been idle for longer than this, in seconds.'));
	o.datatype = 'uinteger';
	o.placeholder = '30';
	o.depends('type', 'anytls');
	o.modalonly = true;

	o = s.option(form.Value, 'anytls_min_idle_session', _('Minimum idle sessions'),
		_('In the check, at least the first <code>n</code> idle sessions are kept open.'));
	o.datatype = 'uinteger';
	o.placeholder = '0';
	o.depends('type', 'anytls');
	o.modalonly = true;
	/* AnyTLS config end */

	/* Hysteria (2) config start */
	o = s.option(form.DynamicList, 'hysteria_hopping_port', _('Hopping port'));
	o.depends('type', 'hysteria');
	o.depends('type', 'hysteria2');
	o.validate = hp.validatePortRange;
	o.modalonly = true;

	o = s.option(form.Value, 'hysteria_hop_interval', _('Hop interval'),
		_('Port hopping interval in seconds.'));
	o.datatype = 'uinteger';
	o.placeholder = '30';
	o.depends({'type': 'hysteria', 'hysteria_hopping_port': /[\s\S]/});
	o.depends({'type': 'hysteria2', 'hysteria_hopping_port': /[\s\S]/});
	o.modalonly = true;

	o = s.option(form.ListValue, 'hysteria_protocol', _('Protocol'));
	o.value('udp');
	/* WeChat-Video / FakeTCP are unsupported by sing-box currently
	 * o.value('wechat-video');
	 * o.value('faketcp');
	 */
	o.default = 'udp';
	o.depends('type', 'hysteria');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.ListValue, 'hysteria_auth_type', _('Authentication type'));
	o.value('', _('Disable'));
	o.value('base64', _('Base64'));
	o.value('string', _('String'));
	o.depends('type', 'hysteria');
	o.modalonly = true;

	o = s.option(form.Value, 'hysteria_auth_payload', _('Authentication payload'));
	o.password = true
	o.depends({'type': 'hysteria', 'hysteria_auth_type': /[\s\S]/});
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.ListValue, 'hysteria_obfs_type', _('Obfuscate type'));
	o.value('', _('Disable'));
	o.value('salamander', _('Salamander'));
	o.depends('type', 'hysteria2');
	o.modalonly = true;

	o = s.option(form.Value, 'hysteria_obfs_password', _('Obfuscate password'));
	o.password = true;
	o.depends('type', 'hysteria');
	o.depends({'type': 'hysteria2', 'hysteria_obfs_type': /[\s\S]/});
	o.modalonly = true;

	o = s.option(form.Value, 'hysteria_down_mbps', _('Max download speed'),
		_('Max download speed in Mbps.'));
	o.datatype = 'uinteger';
	o.depends('type', 'hysteria');
	o.depends('type', 'hysteria2');
	o.modalonly = true;

	o = s.option(form.Value, 'hysteria_up_mbps', _('Max upload speed'),
		_('Max upload speed in Mbps.'));
	o.datatype = 'uinteger';
	o.depends('type', 'hysteria');
	o.depends('type', 'hysteria2');
	o.modalonly = true;

	o = s.option(form.Value, 'hysteria_recv_window_conn', _('QUIC stream receive window'),
		_('The QUIC stream-level flow control window for receiving data.'));
	o.datatype = 'uinteger';
	o.depends('type', 'hysteria');
	o.modalonly = true;

	o = s.option(form.Value, 'hysteria_revc_window', _('QUIC connection receive window'),
		_('The QUIC connection-level flow control window for receiving data.'));
	o.datatype = 'uinteger';
	o.depends('type', 'hysteria');
	o.modalonly = true;

	o = s.option(form.Flag, 'hysteria_disable_mtu_discovery', _('Disable Path MTU discovery'),
		_('Disables Path MTU Discovery (RFC 8899). Packets will then be at most 1252 (IPv4) / 1232 (IPv6) bytes in size.'));
	o.depends('type', 'hysteria');
	o.modalonly = true;
	/* Hysteria (2) config end */

	/* Shadowsocks config start */

	o = s.option(form.Value, 'hysteria2_hop_interval_max', _('Maximum hop interval'),
		_('Upper bound of the randomized port hopping interval, e.g. <code>60s</code>.'));
	o.depends({'type': 'hysteria2', 'hysteria_hopping_port': /[\s\S]/});
	o.modalonly = true;

	o = s.option(form.ListValue, 'hysteria2_bbr_profile', _('BBR profile'),
		_('Congestion control profile used by the BBR sender.'));
	o.value('', _('default (standard)'));
	o.value('standard', _('standard'));
	o.value('conservative', _('conservative'));
	o.value('aggressive', _('aggressive'));
	o.depends('type', 'hysteria2');
	o.modalonly = true;

	o = s.option(form.Flag, 'hysteria2_brutal_debug', _('Brutal debug'),
		_('Log the bandwidth estimation details of the brutal congestion control.'));
	o.depends('type', 'hysteria2');
	o.modalonly = true;

	o = s.option(form.Flag, 'hysteria2_disable_chrome_parrot', _('Disable Chrome QUIC fingerprint'),
		_('Do not mimic the Chrome QUIC handshake.'));
	o.depends('type', 'hysteria2');
	o.modalonly = true;

	o = s.option(form.Flag, 'hysteria2_realm', _('Realm (NAT traversal)'),
		_('Let the server publish its address through a realm service and STUN.') +
		'<br/>' +
		_('The address and port above are ignored while this is enabled.'));
	o.depends('type', 'hysteria2');
	o.modalonly = true;

	o = s.option(form.Value, 'hysteria2_realm_server_url', _('Realm server URL'),
		_('e.g. <code>https://realm.example.com</code>.'));
	o.depends({'type': 'hysteria2', 'hysteria2_realm': '1'});
	o.modalonly = true;

	o = s.option(form.Value, 'hysteria2_realm_token', _('Realm token'));
	o.password = true;
	o.depends({'type': 'hysteria2', 'hysteria2_realm': '1'});
	o.modalonly = true;

	o = s.option(form.Value, 'hysteria2_realm_id', _('Realm ID'));
	o.depends({'type': 'hysteria2', 'hysteria2_realm': '1'});
	o.modalonly = true;

	o = s.option(form.DynamicList, 'hysteria2_realm_stun_servers', _('STUN servers'),
		_('One STUN server per line, e.g. <code>stun.example.com:3478</code>.'));
	o.depends({'type': 'hysteria2', 'hysteria2_realm': '1'});
	o.modalonly = true;

	o = s.option(form.ListValue, 'hysteria2_realm_ip_version', _('Realm IP version'));
	o.value('', _('default'));
	o.value('4', 'IPv4');
	o.value('6', 'IPv6');
	o.depends({'type': 'hysteria2', 'hysteria2_realm': '1'});
	o.modalonly = true;

	o = s.option(form.Flag, 'hysteria2_realm_port_mapping', _('Realm port mapping'),
		_('Ask the realm service to allocate a public port.'));
	o.depends({'type': 'hysteria2', 'hysteria2_realm': '1'});
	o.modalonly = true;

	o = s.option(form.Value, 'hysteria2_realm_port_mapping_timeout', _('Port mapping timeout'),
		_('In seconds, empty uses the core default.'));
	o.datatype = 'uinteger';
	o.depends({'type': 'hysteria2', 'hysteria2_realm': '1', 'hysteria2_realm_port_mapping': '1'});
	o.modalonly = true;

	o = s.option(form.Value, 'hysteria2_realm_port_mapping_lifetime', _('Port mapping lifetime'),
		_('In seconds, empty uses the core default.'));
	o.datatype = 'uinteger';
	o.depends({'type': 'hysteria2', 'hysteria2_realm': '1', 'hysteria2_realm_port_mapping': '1'});
	o.modalonly = true;

	o = s.option(form.ListValue, 'shadowsocks_encrypt_method', _('Encrypt method'));
	for (let i of hp.shadowsocks_encrypt_methods)
		o.value(i);
	/* Stream ciphers */
	o.value('aes-128-ctr');
	o.value('aes-192-ctr');
	o.value('aes-256-ctr');
	o.value('aes-128-cfb');
	o.value('aes-192-cfb');
	o.value('aes-256-cfb');
	o.value('chacha20');
	o.value('chacha20-ietf');
	o.value('rc4-md5');
	o.default = 'aes-128-gcm';
	o.depends('type', 'shadowsocks');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.ListValue, 'shadowsocks_plugin', _('Plugin'));
	o.value('', _('none'));
	o.value('obfs-local');
	o.value('v2ray-plugin');
	o.depends('type', 'shadowsocks');
	o.modalonly = true;

	o = s.option(form.Value, 'shadowsocks_plugin_opts', _('Plugin opts'));
	o.depends('shadowsocks_plugin', 'obfs-local');
	o.depends('shadowsocks_plugin', 'v2ray-plugin');
	o.modalonly = true;
	/* Shadowsocks config end */

	/* ShadowTLS config */
	o = s.option(form.ListValue, 'shadowtls_version', _('ShadowTLS version'));
	o.value('1', _('v1'));
	o.value('2', _('v2'));
	o.value('3', _('v3'));
	o.default = '1';
	o.depends('type', 'shadowtls');
	o.rmempty = false;
	o.modalonly = true;

	/* Socks config */
	o = s.option(form.ListValue, 'socks_version', _('Socks version'));
	o.value('4', _('Socks4'));
	o.value('4a', _('Socks4A'));
	o.value('5', _('Socks5'));
	o.default = '5';
	o.depends('type', 'socks');
	o.rmempty = false;
	o.modalonly = true;

	/* SSH config start */
	o = s.option(form.Value, 'ssh_client_version', _('Client version'),
		_('Random version will be used if empty.'));
	o.depends('type', 'ssh');
	o.modalonly = true;

	o = s.option(form.DynamicList, 'ssh_host_key', _('Host key'),
		_('Accept any if empty.'));
	o.depends('type', 'ssh');
	o.modalonly = true;

	o = s.option(form.DynamicList, 'ssh_host_key_algo', _('Host key algorithms'))
	o.depends('type', 'ssh');
	o.modalonly = true;

	o = s.option(form.DynamicList, 'ssh_priv_key', _('Private key'));
	o.password = true;
	o.depends('type', 'ssh');
	o.modalonly = true;

	o = s.option(form.Value, 'ssh_priv_key_pp', _('Private key passphrase'));
	o.password = true;
	o.depends('type', 'ssh');
	o.modalonly = true;
	/* SSH config end */

	/* TUIC config start */
	o = s.option(form.Value, 'uuid', _('UUID'));
	o.password = true;
	o.depends('type', 'tuic');
	o.depends('type', 'vless');
	o.depends('type', 'vmess');
	o.validate = hp.validateUUID;
	o.modalonly = true;

	o = s.option(form.ListValue, 'tuic_congestion_control', _('Congestion control algorithm'),
		_('QUIC congestion control algorithm.'));
	o.value('cubic', _('CUBIC'));
	o.value('new_reno', _('New Reno'));
	o.value('bbr', _('BBR'));
	o.default = 'cubic';
	o.depends('type', 'tuic');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.ListValue, 'tuic_udp_relay_mode', _('UDP relay mode'),
		_('UDP packet relay mode.'));
	o.value('', _('Default'));
	o.value('native', _('Native'));
	o.value('quic', _('QUIC'));
	o.depends('type', 'tuic');
	o.modalonly = true;

	o = s.option(form.Flag, 'tuic_udp_over_stream', _('UDP over stream'),
		_('This is the TUIC port of the UDP over TCP protocol, designed to provide a QUIC stream based UDP relay mode that TUIC does not provide.'));
	o.depends({'type': 'tuic','tuic_udp_relay_mode': ''});
	o.modalonly = true;

	o = s.option(form.Flag, 'tuic_enable_zero_rtt', _('Enable 0-RTT handshake'),
		_('Enable 0-RTT QUIC connection handshake on the client side. This is not impacting much on the performance, as the protocol is fully multiplexed.<br/>' +
			'Disabling this is highly recommended, as it is vulnerable to replay attacks.'));
	o.depends('type', 'tuic');
	o.modalonly = true;

	o = s.option(form.Value, 'tuic_heartbeat', _('Heartbeat interval'),
		_('Interval for sending heartbeat packets for keeping the connection alive (in seconds).'));
	o.datatype = 'uinteger';
	o.default = '10';
	o.depends('type', 'tuic');
	o.modalonly = true;
	/* Tuic config end */

	/* VMess / VLESS config start */
	o = s.option(form.ListValue, 'vless_flow', _('Flow'));
	o.value('', _('None'));
	o.value('xtls-rprx-vision');
	o.depends('type', 'vless');
	o.modalonly = true;

	o = s.option(form.Value, 'vmess_alterid', _('Alter ID'),
		_('Legacy protocol support (VMess MD5 Authentication) is provided for compatibility purposes only, use of alterId > 1 is not recommended.'));
	o.datatype = 'uinteger';
	o.depends('type', 'vmess');
	o.modalonly = true;

	o = s.option(form.ListValue, 'vmess_encrypt', _('Encrypt method'));
	o.value('auto');
	o.value('none');
	o.value('zero');
	o.value('aes-128-gcm');
	o.value('chacha20-poly1305');
	o.default = 'auto';
	o.depends('type', 'vmess');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Flag, 'vmess_global_padding', _('Global padding'),
		_('Protocol parameter. Will waste traffic randomly if enabled (enabled by default in v2ray and cannot be disabled).'));
	o.default = o.enabled;
	o.depends('type', 'vmess');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Flag, 'vmess_authenticated_length', _('Authenticated length'),
		_('Protocol parameter. Enable length block encryption.'));
	o.depends('type', 'vmess');
	o.modalonly = true;
	/* VMess config end */

	/* Transport config start */
	o = s.option(form.ListValue, 'transport', _('Transport'),
		_('No TCP transport, plain HTTP is merged into the HTTP transport.'));
	o.value('', _('None'));
	o.value('grpc', _('gRPC'));
	o.value('http', _('HTTP'));
	o.value('httpupgrade', _('HTTPUpgrade'));
	o.value('quic', _('QUIC'));
	o.value('ws', _('WebSocket'));
	o.value('xhttp', _('XHTTP'));
	o.depends('type', 'trojan');
	o.depends('type', 'vless');
	o.depends('type', 'vmess');
	o.onchange = function(ev, section_id, value) {
		let desc = this.map.findElement('id', 'cbid.homeproxy.%s.transport'.format(section_id)).nextElementSibling;
		if (value === 'http')
			desc.innerHTML = _('TLS is not enforced. If TLS is not configured, plain HTTP 1.1 is used.');
		else if (value === 'quic')
			desc.innerHTML = _('No additional encryption support: It\'s basically duplicate encryption.');
		else if (value === 'xhttp')
			desc.innerHTML = _('Xray-core XHTTP transport. Requires a sing-box core with XHTTP support.');
		else
			desc.innerHTML = _('No TCP transport, plain HTTP is merged into the HTTP transport.');

		let tls = this.map.findElement('id', 'cbid.homeproxy.%s.tls'.format(section_id)).firstElementChild;
		if ((value === 'http' && tls.checked) || (value === 'grpc' && !features.with_grpc)) {
			this.map.findElement('id', 'cbid.homeproxy.%s.http_idle_timeout'.format(section_id)).nextElementSibling.innerHTML =
				_('Specifies the period of time (in seconds) after which a health check will be performed using a ping frame if no frames have been received on the connection.<br/>' +
					'Please note that a ping response is considered a received frame, so if there is no other traffic on the connection, the health check will be executed every interval.');

			this.map.findElement('id', 'cbid.homeproxy.%s.http_ping_timeout'.format(section_id)).nextElementSibling.innerHTML =
				_('Specifies the timeout duration (in seconds) after sending a PING frame, within which a response must be received.<br/>' +
					'If a response to the PING frame is not received within the specified timeout duration, the connection will be closed.');
		} else if (value === 'grpc' && features.with_grpc) {
			this.map.findElement('id', 'cbid.homeproxy.%s.http_idle_timeout'.format(section_id)).nextElementSibling.innerHTML =
				_('If the transport doesn\'t see any activity after a duration of this time (in seconds), it pings the client to check if the connection is still active.');

			this.map.findElement('id', 'cbid.homeproxy.%s.http_ping_timeout'.format(section_id)).nextElementSibling.innerHTML =
				_('The timeout (in seconds) that after performing a keepalive check, the client will wait for activity. If no activity is detected, the connection will be closed.');
		}
	}
	o.modalonly = true;

	/* gRPC config start */
	o = s.option(form.Value, 'grpc_servicename', _('gRPC service name'));
	o.depends('transport', 'grpc');
	o.modalonly = true;

	if (features.with_grpc) {
		o = s.option(form.Flag, 'grpc_permit_without_stream', _('gRPC permit without stream'),
			_('If enabled, the client transport sends keepalive pings even with no active connections.'));
		o.depends('transport', 'grpc');
		o.modalonly = true;
	}
	/* gRPC config end */

	/* HTTP(Upgrade) config start */
	o = s.option(form.DynamicList, 'http_host', _('Host'));
	o.datatype = 'hostname';
	o.depends('transport', 'http');
	o.modalonly = true;

	o = s.option(form.Value, 'httpupgrade_host', _('Host'));
	o.datatype = 'hostname';
	o.depends('transport', 'httpupgrade');
	o.modalonly = true;

	o = s.option(form.Value, 'http_path', _('Path'));
	o.depends('transport', 'http');
	o.depends('transport', 'httpupgrade');
	o.modalonly = true;

	o = s.option(form.Value, 'http_method', _('Method'));
	o.value('GET', _('GET'));
	o.value('PUT', _('PUT'));
	o.depends('transport', 'http');
	o.modalonly = true;

	o = s.option(form.Value, 'http_idle_timeout', _('Idle timeout'),
		_('Specifies the period of time (in seconds) after which a health check will be performed using a ping frame if no frames have been received on the connection.<br/>' +
			'Please note that a ping response is considered a received frame, so if there is no other traffic on the connection, the health check will be executed every interval.'));
	o.datatype = 'uinteger';
	o.depends('transport', 'grpc');
	o.depends({'transport': 'http', 'tls': '1'});
	o.modalonly = true;

	o = s.option(form.Value, 'http_ping_timeout', _('Ping timeout'),
		_('Specifies the timeout duration (in seconds) after sending a PING frame, within which a response must be received.<br/>' +
			'If a response to the PING frame is not received within the specified timeout duration, the connection will be closed.'));
	o.datatype = 'uinteger';
	o.depends('transport', 'grpc');
	o.depends({'transport': 'http', 'tls': '1'});
	o.modalonly = true;
	/* HTTP config end */

	/* WebSocket config start */
	o = s.option(form.Value, 'ws_host', _('Host'));
	o.depends('transport', 'ws');
	o.modalonly = true;

	o = s.option(form.Value, 'ws_path', _('Path'));
	o.depends('transport', 'ws');
	o.modalonly = true;

	o = s.option(form.Value, 'websocket_early_data', _('Early data'),
		_('Allowed payload size is in the request.'));
	o.datatype = 'uinteger';
	o.value('2048');
	o.depends('transport', 'ws');
	o.modalonly = true;

	o = s.option(form.Value, 'websocket_early_data_header', _('Early data header name'));
	o.value('Sec-WebSocket-Protocol');
	o.depends('transport', 'ws');
	o.modalonly = true;
	/* WebSocket config end */

	/* XHTTP config start */
	o = s.option(form.ListValue, 'xhttp_mode', _('XHTTP mode'));
	o.value('', _('auto'));
	o.value('packet-up');
	o.value('stream-up');
	o.value('stream-one');
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.ListValue, 'xhttp_domain_strategy', _('Domain strategy'),
		_('How to resolve the server address before dialing. Empty uses the outbound default.'));
	o.value('', _('default'));
	o.value('prefer_ipv4');
	o.value('prefer_ipv6');
	o.value('ipv4_only');
	o.value('ipv6_only');
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_host', _('Host'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_path', _('Path'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_padding_bytes', _('Padding bytes'),
		_('Range of random padding size, e.g. <code>100-1000</code>.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Flag, 'xhttp_no_grpc_header', _('No gRPC header'),
		_('Disable the gRPC-style framing header (stream-up/stream-one modes, client only).'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_sc_max_each_post_bytes', _('Max bytes per POST'),
		_('packet-up mode only.'));
	o.datatype = 'uinteger';
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_sc_min_posts_interval_ms', _('Min POST interval (ms)'),
		_('packet-up mode only, client side.'));
	o.datatype = 'uinteger';
	o.depends('transport', 'xhttp');
	o.modalonly = true;


	o = s.option(form.Value, 'xhttp_sc_max_buffered_posts', _('Max buffered POSTs'),
		_('packet-up mode only.'));
	o.datatype = 'uinteger';
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_sc_stream_up_server_secs', _('Stream-up server timeout range (s)'),
		_('Range, e.g. <code>5-10</code>.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_server_max_header_bytes', _('Max header bytes'),
		_('Upper bound of the request header size.'));
	o.datatype = 'uinteger';
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Flag, 'xhttp_no_sse_header', _('No SSE header'),
		_('Do not send the <code>text/event-stream</code> content type.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.DynamicList, 'xhttp_trusted_x_forwarded_for', _('Trusted X-Forwarded-For'),
		_('IPs/CIDRs of the proxies allowed to supply the client address via X-Forwarded-For.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;
	o = s.option(form.Value, 'xhttp_xmux_max_concurrency', _('Xmux max concurrency'),
		_('h2/h3 stream concurrency range, e.g. <code>16-32</code>. Client only.<br/>' +
			'It cannot be combined with <em>max connections</em>, that one is ignored when this is set.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_xmux_max_connections', _('Xmux max connections'),
		_('Client only. Ignored when <em>max concurrency</em> is set, the core rejects both together.'));
	o.datatype = 'uinteger';
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_xmux_c_max_reuse_times', _('Xmux max connection reuse times'),
		_('Client only.'));
	o.datatype = 'uinteger';
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_xmux_h_max_request_times', _('Xmux max requests per connection'),
		_('Range, e.g. <code>600-900</code>. Client only.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_xmux_h_max_reusable_secs', _('Xmux max connection lifetime (s)'),
		_('Range, e.g. <code>1800-3000</code>. Client only.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_xmux_h_keep_alive_period', _('Xmux H2 keepalive period (s)'),
		_('H2 PING interval in seconds. 0 uses the 30s default, -1 disables it. Client only.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_method', _('Uplink method'),
		_('HTTP method used for uplink POST requests. Defaults to <code>POST</code>. Client only.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.ListValue, 'xhttp_congestion_controller', _('Congestion controller'),
		_('h3 (QUIC/HTTP3) only.'));
	o.value('', _('default'));
	o.value('bbr');
	o.value('cubic');
	o.value('reno');
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_cwnd', _('Initial congestion window'),
		_('h3 only. Initial congestion window in packets. Default 32.'));
	o.datatype = 'uinteger';
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.DynamicList, 'xhttp_headers', _('Headers'),
		_('Extra HTTP request/response headers, one <code>Key: Value</code> pair per line.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_host', _('Download host'),
		_('Host used for the separate stream-down download leg, if different from the main Host.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_path', _('Download path'),
		_('Path used for the separate stream-down download leg, if different from the main Path.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_server', _('Download server'),
		_('Server address for the download leg, if it should go to a different host entirely (e.g. a separate CDN endpoint). Leave empty to use the main server.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_server_port', _('Download server port'));
	o.datatype = 'port';
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.ListValue, 'xhttp_download_domain_strategy', _('Download domain strategy'));
	o.value('', _('default'));
	o.value('prefer_ipv4');
	o.value('prefer_ipv6');
	o.value('ipv4_only');
	o.value('ipv6_only');
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_padding_bytes', _('Download padding bytes'),
		_('Range of random padding size for the download leg. Falls back to the main padding bytes above if left empty.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Flag, 'xhttp_download_tls', _('Download TLS'),
		_('Enable a separate TLS configuration for the download leg. Only needed if the download server/host differs from the main one. The download leg does <strong>not</strong> inherit the main TLS settings: when this is disabled, the download requests are sent over plain HTTP.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_tls_server_name', _('Download TLS server name'));
	o.depends({'transport': 'xhttp', 'xhttp_download_tls': '1'});
	o.modalonly = true;

	o = s.option(form.DynamicList, 'xhttp_download_tls_alpn', _('Download TLS ALPN'));
	o.depends({'transport': 'xhttp', 'xhttp_download_tls': '1'});
	o.modalonly = true;

	o = s.option(form.Flag, 'xhttp_download_tls_insecure', _('Download TLS insecure'),
		_('Skip the certificate verification for the download leg. Only use it with a self-signed endpoint.'));
	o.depends({'transport': 'xhttp', 'xhttp_download_tls': '1'});
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_detour', _('Download detour'),
		_('Tag of another outbound to route the download leg through.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.DynamicList, 'xhttp_download_headers', _('Download headers'),
		_('Extra HTTP request/response headers for the download leg, one <code>Key: Value</code> pair per line.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_method', _('Download uplink method'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.ListValue, 'xhttp_download_congestion_controller', _('Download congestion controller'),
		_('h3 (QUIC/HTTP3) only.'));
	o.value('', _('default'));
	o.value('bbr');
	o.value('cubic');
	o.value('reno');
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_cwnd', _('Download initial congestion window'));
	o.datatype = 'uinteger';
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Flag, 'xhttp_download_no_grpc_header', _('Download disable gRPC header'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Flag, 'xhttp_download_x_padding_obfs_mode', _('Download padding obfuscation mode'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.ListValue, 'xhttp_download_x_padding_placement', _('Download padding placement'));
	o.value('queryInHeader');
	o.value('query');
	o.value('header');
	o.value('cookie');
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_x_padding_key', _('Download padding key'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_x_padding_header', _('Download padding header'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.ListValue, 'xhttp_download_x_padding_method', _('Download padding method'));
	o.value('repeat-x');
	o.value('tokenish');
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.ListValue, 'xhttp_download_session_placement', _('Download session placement'));
	o.value('path');
	o.value('query');
	o.value('header');
	o.value('cookie');
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_session_key', _('Download session key'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.ListValue, 'xhttp_download_seq_placement', _('Download seq placement'));
	o.value('path');
	o.value('query');
	o.value('header');
	o.value('cookie');
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_seq_key', _('Download seq key'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.ListValue, 'xhttp_download_uplink_data_placement', _('Download uplink data placement'));
	o.value('body');
	o.value('header');
	o.value('cookie');
	o.value('auto');
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_uplink_data_key', _('Download uplink data key'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_uplink_chunk_size', _('Download uplink chunk size'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;


	o = s.option(form.Value, 'xhttp_download_sc_max_each_post_bytes', _('Download max bytes per POST'),
		_('packet-up mode only.'));
	o.datatype = 'uinteger';
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_sc_min_posts_interval_ms', _('Download min POST interval (ms)'),
		_('packet-up mode only.'));
	o.datatype = 'uinteger';
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_sc_max_buffered_posts', _('Download max buffered POSTs'),
		_('packet-up mode only.'));
	o.datatype = 'uinteger';
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_sc_stream_up_server_secs', _('Download stream-up server timeout range (s)'),
		_('Range, e.g. <code>5-10</code>.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_server_max_header_bytes', _('Download max header bytes'));
	o.datatype = 'uinteger';
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Flag, 'xhttp_download_no_sse_header', _('Download no SSE header'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.DynamicList, 'xhttp_download_trusted_x_forwarded_for', _('Download trusted X-Forwarded-For'),
		_('IPs/CIDRs of the proxies allowed to supply the client address via X-Forwarded-For.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_session_id_table', _('Download session ID character table'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_session_id_length', _('Download session ID length range'),
		_('Range, e.g. <code>8-16</code>.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;
	o = s.option(form.Value, 'xhttp_download_xmux_max_concurrency', _('Download xmux max concurrency'),
		_('Cannot be combined with the download <em>max connections</em>, that one is ignored when this is set.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_xmux_max_connections', _('Download xmux max connections'),
		_('Ignored when the download <em>max concurrency</em> is set.'));
	o.datatype = 'uinteger';
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_xmux_c_max_reuse_times', _('Download xmux max reuse times'));
	o.datatype = 'uinteger';
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_xmux_h_max_request_times', _('Download xmux h2/h3 max request times'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_xmux_h_max_reusable_secs', _('Download xmux h2/h3 max reusable secs'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_download_xmux_h_keep_alive_period', _('Download xmux h2/h3 keep-alive period'));
	o.datatype = 'uinteger';
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Flag, 'xhttp_x_padding_obfs_mode', _('Padding obfuscation mode'),
		_('When disabled (default), padding is written via Referer-with-query for out-of-the-box interop. Enable to use the placement/key/header/method fields below.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.ListValue, 'xhttp_x_padding_placement', _('Padding placement'));
	o.value('queryInHeader', _('queryInHeader (default)'));
	o.value('query', _('query'));
	o.value('header', _('header'));
	o.value('cookie', _('cookie'));
	o.depends({'transport': 'xhttp', 'xhttp_x_padding_obfs_mode': '1'});
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_x_padding_key', _('Padding key'),
		_('Header/cookie/query name for padding. Default <code>x_padding</code>.'));
	o.depends({'transport': 'xhttp', 'xhttp_x_padding_obfs_mode': '1'});
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_x_padding_header', _('Padding header'),
		_('Header name used for header placement. Default <code>X-Padding</code>.'));
	o.depends({'transport': 'xhttp', 'xhttp_x_padding_obfs_mode': '1'});
	o.modalonly = true;

	o = s.option(form.ListValue, 'xhttp_x_padding_method', _('Padding method'));
	o.value('repeat-x', _('repeat-x'));
	o.value('tokenish', _('tokenish'));
	o.depends({'transport': 'xhttp', 'xhttp_x_padding_obfs_mode': '1'});
	o.modalonly = true;

	o = s.option(form.ListValue, 'xhttp_session_placement', _('Session ID placement'));
	o.value('path', _('path'));
	o.value('query', _('query'));
	o.value('header', _('header'));
	o.value('cookie', _('cookie'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_session_key', _('Session ID key'),
		_('Header/cookie/query name; default depends on placement.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_session_id_table', _('Session ID character table'),
		_('A predefined name (e.g. <code>hex</code>, <code>base62</code>) or a literal charset, used to generate a random session ID instead of a UUID.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_session_id_length', _('Session ID length range'),
		_('Range, e.g. <code>16-24</code>. Requires the character table above to be set.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.ListValue, 'xhttp_seq_placement', _('Sequence placement'));
	o.value('path', _('path'));
	o.value('query', _('query'));
	o.value('header', _('header'));
	o.value('cookie', _('cookie'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_seq_key', _('Sequence key'),
		_('Header/cookie/query name; default depends on placement.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.ListValue, 'xhttp_uplink_data_placement', _('Uplink data placement'));
	o.value('body', _('body (default)'));
	o.value('header', _('header'));
	o.value('cookie', _('cookie'));
	o.value('auto', _('auto'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_uplink_data_key', _('Uplink data key'),
		_('Header/cookie name prefix used for header/cookie placement.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;

	o = s.option(form.Value, 'xhttp_uplink_chunk_size', _('Uplink chunk size range'),
		_('Range, e.g. <code>100000-200000</code>.'));
	o.depends('transport', 'xhttp');
	o.modalonly = true;
	/* XHTTP config end */

	o = s.option(form.ListValue, 'packet_encoding', _('Packet encoding'));
	o.value('', _('none'));
	o.value('packetaddr', _('packet addr (v2ray-core v5+)'));
	o.value('xudp', _('Xudp (Xray-core)'));
	o.depends('type', 'vless');
	o.depends('type', 'vmess');
	o.modalonly = true;
	/* Transport config end */

	/* Wireguard config start */
	o = s.option(form.DynamicList, 'wireguard_local_address', _('Local address'),
		_('List of IP (v4 or v6) addresses prefixes to be assigned to the interface.'));
	o.datatype = 'cidr';
	o.depends('type', 'wireguard');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Value, 'wireguard_private_key', _('Private key'),
		_('WireGuard requires base64-encoded private keys.'));
	o.password = true;
	o.depends('type', 'wireguard');
	o.validate = L.bind(hp.validateBase64Key, this, 44);
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Value, 'wireguard_peer_public_key', _('Peer public key'),
		_('WireGuard peer public key.'));
	o.depends('type', 'wireguard');
	o.validate = L.bind(hp.validateBase64Key, this, 44);
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Value, 'wireguard_pre_shared_key', _('Pre-shared key'),
		_('WireGuard pre-shared key.'));
	o.password = true;
	o.depends('type', 'wireguard');
	o.validate = L.bind(hp.validateBase64Key, this, 44);
	o.modalonly = true;

	o = s.option(form.DynamicList, 'wireguard_reserved', _('Reserved field bytes'));
	o.datatype = 'integer';
	o.depends('type', 'wireguard');
	o.modalonly = true;

	o = s.option(form.Value, 'wireguard_mtu', _('MTU'));
	o.datatype = 'range(0,9000)';
	o.placeholder = '1408';
	o.depends('type', 'wireguard');
	o.modalonly = true;

	o = s.option(form.Value, 'wireguard_persistent_keepalive_interval', _('Persistent keepalive interval'),
		_('In seconds. Disabled by default.'));
	o.datatype = 'uinteger';
	o.depends('type', 'wireguard');
	o.modalonly = true;
	/* Wireguard config end */

	/* Mux config start */
	o = s.option(form.Flag, 'multiplex', _('Multiplex'));
	o.depends('type', 'shadowsocks');
	o.depends('type', 'trojan');
	o.depends('type', 'vless');
	o.depends('type', 'vmess');
	o.modalonly = true;

	o = s.option(form.ListValue, 'multiplex_protocol', _('Protocol'),
		_('Multiplex protocol.'));
	o.value('h2mux');
	o.value('smux');
	o.value('yamux');
	o.default = 'h2mux';
	o.depends('multiplex', '1');
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Value, 'multiplex_max_connections', _('Maximum connections'));
	o.datatype = 'uinteger';
	o.depends('multiplex', '1');
	o.modalonly = true;

	o = s.option(form.Value, 'multiplex_min_streams', _('Minimum streams'),
		_('Minimum multiplexed streams in a connection before opening a new connection.'));
	o.datatype = 'uinteger';
	o.depends('multiplex', '1');
	o.modalonly = true;

	o = s.option(form.Value, 'multiplex_max_streams', _('Maximum streams'),
		_('Maximum multiplexed streams in a connection before opening a new connection.<br/>' +
			'Conflict with <code>%s</code> and <code>%s</code>.').format(
				_('Maximum connections'), _('Minimum streams')));
	o.datatype = 'uinteger';
	o.depends({'multiplex': '1', 'multiplex_max_connections': '', 'multiplex_min_streams': ''});
	o.modalonly = true;

	o = s.option(form.Flag, 'multiplex_padding', _('Enable padding'));
	o.depends('multiplex', '1');
	o.modalonly = true;

	o = s.option(form.Flag, 'multiplex_brutal', _('Enable TCP Brutal'),
		_('Enable TCP Brutal congestion control algorithm'));
	o.depends('multiplex', '1');
	o.modalonly = true;

	o = s.option(form.Value, 'multiplex_brutal_down', _('Download bandwidth'),
		_('Download bandwidth in Mbps.'));
	o.datatype = 'uinteger';
	o.depends('multiplex_brutal', '1');
	o.modalonly = true;

	o = s.option(form.Value, 'multiplex_brutal_up', _('Upload bandwidth'),
		_('Upload bandwidth in Mbps.'));
	o.datatype = 'uinteger';
	o.depends('multiplex_brutal', '1');
	o.modalonly = true;
	/* Mux config end */

	/* TLS config start */
	o = s.option(form.Flag, 'tls', _('TLS'));
	o.depends('type', 'anytls');
	o.depends('type', 'http');
	o.depends('type', 'hysteria');
	o.depends('type', 'hysteria2');
	o.depends('type', 'shadowtls');
	o.depends('type', 'trojan');
	o.depends('type', 'tuic');
	o.depends('type', 'vless');
	o.depends('type', 'vmess');
	o.validate = function(section_id, _value) {
		if (section_id) {
			let type = this.map.lookupOption('type', section_id)[0].formvalue(section_id);
			let tls = this.map.findElement('id', 'cbid.homeproxy.%s.tls'.format(section_id)).firstElementChild;

			if (['anytls', 'hysteria', 'hysteria2', 'shadowtls', 'tuic'].includes(type)) {
				tls.checked = true;
				tls.disabled = true;
			} else {
				tls.disabled = null;
			}
		}

		return true;
	}
	o.modalonly = true;

	o = s.option(form.Value, 'tls_sni', _('TLS SNI'),
		_('Used to verify the hostname on the returned certificates unless insecure is given.'));
	o.depends('tls', '1');
	o.modalonly = true;

	o = s.option(form.DynamicList, 'tls_alpn', _('TLS ALPN'),
		_('List of supported application level protocols, in order of preference.'));
	o.depends('tls', '1');
	o.modalonly = true;

	o = s.option(form.Flag, 'tls_insecure', _('Allow insecure'),
		_('Allow insecure connection at TLS client.') +
		'<br/>' +
		_('This is <strong>DANGEROUS</strong>, your traffic is almost like <strong>PLAIN TEXT</strong>! Use at your own risk!'));
	o.depends('tls', '1');
	o.onchange = allowInsecureConfirm;
	o.modalonly = true;

	o = s.option(form.Flag, 'tls_fragment', _('TLS fragment'),
		_('Split the ClientHello into several small TLS records to evade SNI based blocking.') +
		'<br/>' +
		_('Client side only, works with every TLS based protocol.'));
	o.depends('tls', '1');
	o.modalonly = true;

	o = s.option(form.Value, 'tls_fragment_fallback_delay', _('Fragment fallback delay'),
		_('How long to wait before falling back to a whole ClientHello, e.g. <code>500ms</code>.') +
		'<br/>' +
		_('Empty uses the core default.'));
	o.depends({'tls': '1', 'tls_fragment': '1'});
	o.modalonly = true;

	o = s.option(form.Flag, 'tls_record_fragment', _('TLS record fragment'),
		_('Fragment at the TLS record layer instead of the handshake message.'));
	o.depends({'tls': '1', 'tls_fragment': '1'});
	o.modalonly = true;

	o = s.option(form.Value, 'tls_spoof', _('TLS spoof host'),
		_('Send a forged ClientHello carrying this server name before the real handshake.') +
		'<br/>' +
		_('Requires a server name above, client side only.') +
		'<br/>' +
		_('Not supported together with REALITY.'));
	o.depends('tls', '1');
	o.modalonly = true;

	o = s.option(form.ListValue, 'tls_spoof_method', _('TLS spoof method'),
		_('Fault injected into the forged packet. <em>wrong-sequence</em> is the core default.') +
		'<br/>' +
		_('Ignored while the spoof host is empty.'));
	o.value('', _('default (wrong-sequence)'));
	o.value('wrong-sequence', _('wrong-sequence'));
	o.value('wrong-checksum', _('wrong-checksum'));
	o.value('wrong-ack', _('wrong-ack'));
	o.value('wrong-md5', _('wrong-md5'));
	o.value('wrong-timestamp', _('wrong-timestamp'));
	o.depends('tls', '1');
	o.modalonly = true;

	o = s.option(form.ListValue, 'tls_min_version', _('Minimum TLS version'),
		_('The minimum TLS version that is acceptable.'));
	o.value('', _('default'));
	for (let i of hp.tls_versions)
		o.value(i);
	o.depends('tls', '1');
	o.modalonly = true;

	o = s.option(form.ListValue, 'tls_max_version', _('Maximum TLS version'),
		_('The maximum TLS version that is acceptable.'));
	o.value('', _('default'));
	for (let i of hp.tls_versions)
		o.value(i);
	o.depends('tls', '1');
	o.modalonly = true;

	o = s.option(hp.CBIStaticList, 'tls_cipher_suites', _('Cipher suites'),
		_('The elliptic curves that will be used in an ECDHE handshake, in preference order. If empty, the default will be used.'));
	for (let i of hp.tls_cipher_suites)
		o.value(i);
	o.depends('tls', '1');
	o.optional = true;
	o.modalonly = true;

	o = s.option(form.Flag, 'tls_self_sign', _('Append self-signed certificate'),
		_('If you have the root certificate, use this option instead of allowing insecure.'));
	o.depends('tls_insecure', '0');
	o.modalonly = true;

	o = s.option(form.Value, 'tls_cert_path', _('Certificate path'),
		_('The path to the server certificate, in PEM format.'));
	o.value('/etc/homeproxy/certs/client_ca.pem');
	o.depends('tls_self_sign', '1');
	o.validate = hp.validateCertificatePath;
	o.rmempty = false;
	o.modalonly = true;

	o = s.option(form.Button, '_upload_cert', _('Upload certificate'),
		_('<strong>Save your configuration before uploading files!</strong>'));
	o.inputstyle = 'action';
	o.inputtitle = _('Upload...');
	o.depends({'tls_self_sign': '1', 'tls_cert_path': '/etc/homeproxy/certs/client_ca.pem'});
	o.onclick = L.bind(hp.uploadCertificate, this, _('certificate'), 'client_ca');
	o.modalonly = true;

	o = s.option(form.Flag, 'tls_ech', _('Enable ECH'),
		_('ECH (Encrypted Client Hello) is a TLS extension that allows a client to encrypt the first part of its ClientHello message.'));
	o.depends('tls', '1');
	o.modalonly = true;

	o = s.option(form.Value, 'tls_ech_config_path', _('ECH config path'),
		_('The path to the ECH config, in PEM format. If empty, load from DNS will be attempted.'));
	o.value('/etc/homeproxy/certs/client_ech_conf.pem');
	o.depends('tls_ech', '1');
	o.modalonly = true;

	o = s.option(form.Button, '_upload_ech_config', _('Upload ECH config'),
		_('<strong>Save your configuration before uploading files!</strong>'));
	o.inputstyle = 'action';
	o.inputtitle = _('Upload...');
	o.depends({'tls_ech': '1', 'tls_ech_config_path': '/etc/homeproxy/certs/client_ech_conf.pem'});
	o.onclick = L.bind(hp.uploadCertificate, this, _('ECH config'), 'client_ech_conf');
	o.modalonly = true;

	if (features.with_utls) {
		o = s.option(form.ListValue, 'tls_utls', _('uTLS fingerprint'),
			_('uTLS is a fork of "crypto/tls", which provides ClientHello fingerprinting resistance.'));
		o.value('', _('Disable'));
		o.value('360');
		o.value('android');
		o.value('chrome');
		o.value('edge');
		o.value('firefox');
		o.value('ios');
		o.value('qq');
		o.value('random');
		o.value('randomized');
		o.value('safari');
		o.depends({'tls': '1', 'type': /^((?!hysteria2?|tuic$).)+$/});
		o.validate = function(section_id, value) {
			if (section_id) {
				let tls_reality = this.map.findElement('id', 'cbid.homeproxy.%s.tls_reality'.format(section_id)).firstElementChild;
				if (tls_reality.checked && !value)
					return _('Expecting: %s').format(_('non-empty value'));

				let vless_flow = this.map.lookupOption('vless_flow', section_id)[0].formvalue(section_id);
				if ((tls_reality.checked || vless_flow) && ['360', 'android'].includes(value))
					return _('Unsupported fingerprint!');
			}

			return true;
		}
		o.modalonly = true;

		o = s.option(form.Flag, 'tls_reality', _('REALITY'));
		o.depends({'tls': '1', 'type': 'anytls'});
		o.depends({'tls': '1', 'type': 'vless'});
		o.modalonly = true;

		o = s.option(form.Value, 'tls_reality_public_key', _('REALITY public key'));
		o.password = true;
		o.depends('tls_reality', '1');
		o.rmempty = false;
		o.modalonly = true;

		o = s.option(form.Value, 'tls_reality_short_id', _('REALITY short ID'));
		o.password = true;
		o.depends('tls_reality', '1');
		o.modalonly = true;
	}
	/* TLS config end */

	/* Extra settings start */
	o = s.option(form.Flag, 'tcp_fast_open', _('TCP fast open'));
	o.modalonly = true;

	o = s.option(form.Flag, 'tcp_multi_path', _('MultiPath TCP'));
	o.modalonly = true;

	o = s.option(form.Flag, 'udp_fragment', _('UDP Fragment'),
		_('Enable UDP fragmentation.'));
	o.modalonly = true;

	o = s.option(form.Flag, 'udp_over_tcp', _('UDP over TCP'),
		_('Enable the SUoT protocol, requires server support. Conflict with multiplex.'));
	o.depends('type', 'socks');
	o.depends({'type': 'shadowsocks', 'multiplex': '0'});
	o.modalonly = true;

	o = s.option(form.ListValue, 'udp_over_tcp_version', _('SUoT version'));
	o.value('1', _('v1'));
	o.value('2', _('v2'));
	o.default = '2';
	o.depends('udp_over_tcp', '1');
	o.modalonly = true;
	/* Extra settings end */

	return s;
}

return view.extend({
	load() {
		return Promise.all([
			uci.load('homeproxy'),
			hp.getBuiltinFeatures()
		]);
	},

	render(data) {
		let m, s, o, ss, so;
		let main_node = uci.get(data[0], 'config', 'main_node');
		let routing_mode = uci.get(data[0], 'config', 'routing_mode');
		let features = data[1];

		/* Cache subscription information, it will be called multiple times */
		let subinfo = [];
		for (let suburl of (uci.get(data[0], 'subscription', 'subscription_url') || [])) {
			const url = new URL(suburl);
			const urlhash = hp.calcStringMD5(suburl.replace(/#.*$/, ''));
			const title = url.hash ? decodeURIComponent(url.hash.slice(1)) : url.hostname;
			subinfo.push({ 'hash': urlhash, 'title': title });
		}

		m = new form.Map('homeproxy', _('Edit nodes'));

		/* Saving the page rerenders sections, clean the URLTest lists of the
		   nodes that were just removed before the changes are committed. */
		const saveMap = m.save;
		m.save = function(cb, silent) {
			return saveMap.call(this, () => Promise.resolve(
				typeof cb === 'function' ? cb() : null
			).then(() => hp.reconcileUrltestNodes(data[0])), silent);
		};

		s = m.section(form.NamedSection, 'subscription', 'homeproxy');

		/* Node settings start */
		/* User nodes start */
		s.tab('node', _('Nodes'));
		o = s.taboption('node', form.SectionValue, '_node', form.GridSection, 'node');
		ss = renderNodeSettings(o.subsection, data, features, main_node, routing_mode);
		ss.addremove = true;
		ss.filter = function(section_id) {
			for (let info of subinfo)
				if (info.hash === uci.get(data[0], section_id, 'grouphash'))
					return false;

			return true;
		}
		/* Import subscription links start */
		/* Thanks to luci-app-shadowsocks-libev */
		ss.handleLinkImport = function() {
			let textarea = new ui.Textarea();
			ui.showModal(_('Import share links'), [
				E('p', _('Support Hysteria, Shadowsocks, Trojan, v2rayN (VMess), and XTLS (VLESS) online configuration delivery standard.')),
				textarea.render(),
				E('div', { class: 'right' }, [
					E('button', {
						class: 'btn',
						click: ui.hideModal
					}, [ _('Cancel') ]),
					'',
					E('button', {
						class: 'btn cbi-button-action',
						click: ui.createHandlerFn(this, () => {
							let input_links = textarea.getValue().trim().split('\n');
							if (input_links && input_links[0]) {
								/* Remove duplicate lines */
								input_links = input_links.reduce((pre, cur) =>
									(!pre.includes(cur) && pre.push(cur), pre), []);

								let allow_insecure = uci.get(data[0], 'subscription', 'allow_insecure');
								let packet_encoding = uci.get(data[0], 'subscription', 'packet_encoding');
								let imported_node = 0;
								input_links.forEach((l) => {
									let config = parseShareLink(l, features);
									if (config) {
										if (config.tls === '1' && allow_insecure === '1')
											config.tls_insecure = '1'
										if (['vless', 'vmess'].includes(config.type))
											config.packet_encoding = packet_encoding

										let nameHash = hp.calcStringMD5(config.label);
										let sid = uci.add(data[0], 'node', nameHash);
										Object.keys(config).forEach((k) => {
											uci.set(data[0], sid, k, config[k]);
										});
										imported_node++;
									}
								});

								if (imported_node === 0)
									ui.addNotification(null, E('p', _('No valid share link found.')));
								else
									ui.addNotification(null, E('p', _('Successfully imported %s nodes of total %s.').format(
										imported_node, input_links.length)));

								return uci.save()
									.then(L.bind(this.map.load, this.map))
									.then(L.bind(this.map.reset, this.map))
									.then(L.ui.hideModal)
									.catch(() => {});
							} else {
								return ui.hideModal();
							}
						})
					}, [ _('Import') ])
				])
			])
		}
		ss.renderSectionAdd = function(/* ... */) {
			let el = form.GridSection.prototype.renderSectionAdd.apply(this, arguments),
				nameEl = el.querySelector('.cbi-section-create-name');

			ui.addValidator(nameEl, 'uciname', true, (v) => {
				let button = el.querySelector('.cbi-section-create > .cbi-button-add');
				let uciconfig = this.uciconfig || this.map.config;

				if (!v) {
					button.disabled = true;
					return true;
				} else if (uci.get(uciconfig, v)) {
					button.disabled = true;
					return _('Expecting: %s').format(_('unique UCI identifier'));
				} else {
					button.disabled = null;
					return true;
				}
			}, 'blur', 'keyup');

			el.appendChild(E('button', {
				'class': 'cbi-button cbi-button-add',
				'title': _('Import share links'),
				'click': ui.createHandlerFn(this, 'handleLinkImport')
			}, [ _('Import share links') ]));

			return el;
		}
		/* Import subscription links end */
		/* User nodes end */

		/* Subscription nodes start */
		for (const info of subinfo) {
			s.tab('sub_' + info.hash, _('Sub (%s)').format(info.title));
			o = s.taboption('sub_' + info.hash, form.SectionValue, '_sub_' + info.hash, form.GridSection, 'node');
			ss = renderNodeSettings(o.subsection, data, features, main_node, routing_mode);
			ss.filter = function(section_id) {
				return (uci.get(data[0], section_id, 'grouphash') === info.hash);
			}
		}
		/* Subscription nodes end */
		/* Node settings end */

		/* Subscriptions settings start */
		s.tab('subscription', _('Subscriptions'));

		o = s.taboption('subscription', form.Flag, 'auto_update', _('Auto update'),
			_('Auto update subscriptions and geodata.'));
		o.rmempty = false;

		o = s.taboption('subscription', form.ListValue, 'auto_update_time', _('Update time'));
		for (let i = 0; i < 24; i++)
			o.value(i, i + ':00');
		o.default = '2';
		o.depends('auto_update', '1');

		o = s.taboption('subscription', form.Flag, 'update_via_proxy', _('Update via proxy'),
			_('Update subscriptions via proxy.'));
		o.rmempty = false;

		o = s.taboption('subscription', form.DynamicList, 'subscription_url', _('Subscription URL-s'),
			_('Support Hysteria, Shadowsocks, Trojan, v2rayN (VMess), and XTLS (VLESS) online configuration delivery standard.'));
		o.validate = function(section_id, value) {
			if (section_id && value) {
				try {
					let url = new URL(value);
					if (!url.hostname)
						return _('Expecting: %s').format(_('valid URL'));
				}
				catch(e) {
					return _('Expecting: %s').format(_('valid URL'));
				}
			}

			return true;
		}

		o = s.taboption('subscription', form.ListValue, 'filter_nodes', _('Filter nodes'),
			_('Drop/keep specific nodes from subscriptions.'));
		o.value('disabled', _('Disable'));
		o.value('blacklist', _('Blacklist mode'));
		o.value('whitelist', _('Whitelist mode'));
		o.default = 'disabled';
		o.rmempty = false;

		o = s.taboption('subscription', form.DynamicList, 'filter_keywords', _('Filter keywords'),
			_('Drop/keep nodes that contain the specific keywords. <a target="_blank" href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions">Regex</a> is supported.'));
		o.depends({'filter_nodes': 'disabled', '!reverse': true});
		o.rmempty = false;

		o = s.taboption('subscription', form.Value, 'user_agent', _('User-Agent'));
		o.placeholder = 'Wget/1.21 (HomeProxy, like v2rayN)';

		o = s.taboption('subscription', form.Flag, 'allow_insecure', _('Allow insecure'),
			_('Allow insecure connection by default when add nodes from subscriptions.') +
			'<br/>' +
			_('This is <strong>DANGEROUS</strong>, your traffic is almost like <strong>PLAIN TEXT</strong>! Use at your own risk!'));
		o.rmempty = false;
		o.onchange = allowInsecureConfirm;

		o = s.taboption('subscription', form.ListValue, 'packet_encoding', _('Default packet encoding'));
		o.value('', _('none'));
		o.value('packetaddr', _('packet addr (v2ray-core v5+)'));
		o.value('xudp', _('Xudp (Xray-core)'));

		o = s.taboption('subscription', form.Button, '_save_subscriptions', _('Save subscriptions settings'),
			_('NOTE: Save current settings before updating subscriptions.'));
		o.inputstyle = 'apply';
		o.inputtitle = _('Save current settings');
		o.onclick = function() {
			return this.map.save(null, true).then(() => {
				ui.changes.apply(true);
			});
		}

		o = s.taboption('subscription', form.Button, '_update_subscriptions', _('Update nodes from subscriptions'));
		o.inputstyle = 'apply';
		o.inputtitle = function(section_id) {
			let sublist = uci.get(data[0], section_id, 'subscription_url') || [];
			if (sublist.length > 0) {
				return _('Update %s subscriptions').format(sublist.length);
			} else {
				this.readonly = true;
				return _('No subscription available')
			}
		}
		o.onclick = function() {
			return fs.exec_direct('/etc/homeproxy/scripts/update_subscriptions.uc').then((res) => {
				return location.reload();
			}).catch((err) => {
				ui.addNotification(null, E('p', _('An error occurred during updating subscriptions: %s').format(err)));
				return this.map.reset();
			});
		}

		o = s.taboption('subscription', form.Button, '_remove_subscriptions', _('Remove all nodes from subscriptions'));
		o.inputstyle = 'reset';
		o.inputtitle = function() {
			let subnodes = [];
			uci.sections(data[0], 'node', (res) => {
				if (res.grouphash)
					subnodes = subnodes.concat(res['.name'])
			});

			if (subnodes.length > 0) {
				return _('Remove %s nodes').format(subnodes.length);
			} else {
				this.readonly = true;
				return _('No subscription node');
			}
		}
		o.onclick = function() {
			let subnodes = [];
			uci.sections(data[0], 'node', (res) => {
				if (res.grouphash)
					subnodes = subnodes.concat(res['.name'])
			});

			for (let i in subnodes)
				uci.remove(data[0], subnodes[i]);

			if (subnodes.includes(uci.get(data[0], 'config', 'main_node')))
				uci.set(data[0], 'config', 'main_node', 'nil');

			this.inputtitle = _('%s nodes removed').format(subnodes.length);
			this.readonly = true;

			return this.map.save(null, true);
		}
		/* Subscriptions settings end */

		return m.render();
	}
});
