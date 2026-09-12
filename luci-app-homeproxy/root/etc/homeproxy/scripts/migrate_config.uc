#!/usr/bin/ucode -S

'use strict';

import { cursor } from 'uci';
import { isEmpty, parseURL, validation } from 'homeproxy';

const uci = cursor();

const uciconfig = 'homeproxy';
uci.load(uciconfig);

const uciinfra = 'infra',
      ucimigration = 'migration',
      ucimain = 'config',
      ucinode = 'node',
      ucidns = 'dns',
      ucidnsserver = 'dns_server',
      ucidnsrule = 'dns_rule',
      ucirouting = 'routing',
      uciroutingrule = 'routing_rule',
      uciserver = 'server',
      uciapprule = 'app_rule';

if (uci.get(uciconfig, uciinfra, 'china_dns_port'))
	uci.delete(uciconfig, uciinfra, 'china_dns_port');

const china_dns_server = uci.get(uciconfig, ucimain, 'china_dns_server');
if (type(china_dns_server) === 'array') {
	uci.set(uciconfig, ucimain, 'china_dns_server', china_dns_server[0]);
} else {
	if (china_dns_server === 'wan_114')
		uci.set(uciconfig, ucimain, 'china_dns_server', '114.114.114.114');
	else if (match(china_dns_server, /,/))
		uci.set(uciconfig, ucimain, 'china_dns_server', split(china_dns_server, ',')[0]);
}

const github_token = uci.get(uciconfig, uciinfra, 'github_token');
if (github_token) {
	uci.set(uciconfig, ucimain, 'github_token', github_token);
	uci.delete(uciconfig, uciinfra, 'github_token')
}

if (!uci.get(uciconfig, uciinfra, 'ntp_server'))
	uci.set(uciconfig, uciinfra, 'ntp_server', 'nil');

if (!isEmpty(uci.get(uciconfig, uciinfra, 'tun_gso')))
	uci.delete(uciconfig, uciinfra, 'tun_gso');

if (!uci.get(uciconfig, ucimigration))
	uci.set(uciconfig, ucimigration, uciconfig);

const migration_crontab = uci.get(uciconfig, ucimigration, 'crontab');
if (!migration_crontab) {
	system('sed -i "/update_crond.sh/d" "/etc/crontabs/root" 2>"/dev/null"');
	uci.set(uciconfig, ucimigration, 'crontab', '1');
}

if (isEmpty(uci.get(uciconfig, ucimain, 'log_level')))
	uci.set(uciconfig, ucimain, 'log_level', 'warn');

if (isEmpty(uci.get(uciconfig, uciserver, 'log_level')))
	uci.set(uciconfig, uciserver, 'log_level', 'warn');

if (uci.get(uciconfig, ucimain, 'routing_port') === 'all')
	uci.delete(uciconfig, ucimain, 'routing_port');

if (uci.get(uciconfig, 'experimental'))
	uci.delete(uciconfig, 'experimental');

const default_dns_server = uci.get(uciconfig, ucidns, 'default_server');
if (default_dns_server === 'block-dns') {
	uci.set(uciconfig, '_migration_dns_final_block', ucidnsrule);
	uci.set(uciconfig, '_migration_dns_final_block', 'label', 'migration_final_block_dns');
	uci.set(uciconfig, '_migration_dns_final_block', 'enabled', '1');
	uci.set(uciconfig, '_migration_dns_final_block', 'mode', 'default');
	uci.set(uciconfig, '_migration_dns_final_block', 'action', 'reject');
	uci.set(uciconfig, ucidns, 'default_server', 'default-dns');
}

const dns_server_migration = {};
uci.foreach(uciconfig, ucidnsserver, (cfg) => {
	if (cfg.address) {
		const addr = parseURL((!match(cfg.address, /:\/\//) ? 'udp://' : '') + (validation('ip6addr', cfg.address) ? `[${cfg.address}]` : cfg.address));
		if (addr.protocol === 'rcode') {
			dns_server_migration[cfg['.name']] = { action: 'predefined' };
			switch (addr.hostname) {
			case 'success':
				dns_server_migration[cfg['.name']].rcode = 'NOERROR';
				break;
			case 'format_error':
				dns_server_migration[cfg['.name']].rcode = 'FORMERR';
				break;
			case 'server_failure':
				dns_server_migration[cfg['.name']].rcode = 'SERVFAIL';
				break;
			case 'name_error':
				dns_server_migration[cfg['.name']].rcode = 'NXDOMAIN';
				break;
			case 'not_implemented':
				dns_server_migration[cfg['.name']].rcode = 'NOTIMP';
				break;
			case 'refused':
			default:
				dns_server_migration[cfg['.name']].rcode = 'REFUSED';
				break;
			}

			uci.delete(uciconfig, cfg['.name']);
			return;
		}
		uci.set(uciconfig, cfg['.name'], 'type', addr.protocol);
		uci.set(uciconfig, cfg['.name'], 'server', addr.hostname);
		uci.set(uciconfig, cfg['.name'], 'server_port', addr.port);
		uci.set(uciconfig, cfg['.name'], 'path', (addr.pathname !== '/') ? addr.pathname : null);
		uci.delete(uciconfig, cfg['.name'], 'address');
	}

	if (cfg.strategy) {
		if (cfg['.name'] === default_dns_server)
			uci.set(uciconfig, ucidns, 'default_strategy', cfg.strategy);
		dns_server_migration[cfg['.name']] = { strategy: cfg.strategy };
		uci.delete(uciconfig, cfg['.name'], 'strategy');
	}

	if (cfg.client_subnet) {
		if (cfg['.name'] === default_dns_server)
			uci.set(uciconfig, ucidns, 'client_subnet', cfg.client_subnet);

		if (isEmpty(dns_server_migration[cfg['.name']]))
			dns_server_migration[cfg['.name']] = {};
		dns_server_migration[cfg['.name']].client_subnet = cfg.client_subnet;
		uci.delete(uciconfig, cfg['.name'], 'client_subnet');
	}
});

uci.foreach(uciconfig, ucidnsrule, (cfg) => {
	if (cfg.outbound) {
		uci.delete(uciconfig, cfg['.name']);
		if (!cfg.enabled)
			return;

		map(cfg.outbound, (outbound) => {
			switch (outbound) {
			case 'direct-out':
			case 'block-out':
				break;
			case 'any-out':
				uci.set(uciconfig, ucirouting, 'default_outbound_dns', cfg.server);
				break;
			default:
				uci.set(uciconfig, cfg.outbound, 'domain_resolver', cfg.server);
				break;
			}
		});

		return;
	}

	if (cfg.rule_set_ipcidr_match_source === '1')
		uci.rename(uciconfig, cfg['.name'], 'rule_set_ipcidr_match_source', 'rule_set_ip_cidr_match_source');

	if (cfg.server === 'block-dns') {
		uci.set(uciconfig, cfg['.name'], 'action', 'reject');
		uci.delete(uciconfig, cfg['.name'], 'server');
	} else if (!cfg.action) {
		uci.set(uciconfig, cfg['.name'], 'action', 'route');
	}

	if (dns_server_migration[cfg.server]) {
		if (dns_server_migration[cfg.server].strategy)
			uci.set(uciconfig, cfg['.name'], 'strategy', dns_server_migration[cfg.server].strategy);

		if (dns_server_migration[cfg.server].client_subnet)
			uci.set(uciconfig, cfg['.name'], 'client_subnet', dns_server_migration[cfg.server].client_subnet);

		if (dns_server_migration[cfg.server].rcode) {
			uci.set(uciconfig, cfg['.name'], 'action', 'predefined');
			uci.set(uciconfig, cfg['.name'], 'rcode', dns_server_migration[cfg.server].rcode);
			uci.delete(uciconfig, cfg['.name'], 'server');
		}
	}
});

uci.foreach(uciconfig, ucinode, (cfg) => {
	if (!isEmpty(cfg.tls_ech_tls_disable_drs))
		uci.delete(uciconfig, cfg['.name'], 'tls_ech_tls_disable_drs');

	if (!isEmpty(cfg.tls_ech_enable_pqss))
		uci.delete(uciconfig, cfg['.name'], 'tls_ech_enable_pqss');

	if (!isEmpty(cfg.wireguard_gso))
		uci.delete(uciconfig, cfg['.name'], 'wireguard_gso');
});

uci.foreach(uciconfig, uciroutingrule, (cfg) => {
	if (cfg.rule_set_ipcidr_match_source === '1')
		uci.rename(uciconfig, cfg['.name'], 'rule_set_ipcidr_match_source', 'rule_set_ip_cidr_match_source');

	if (cfg.outbound === 'block-out') {
		uci.set(uciconfig, cfg['.name'], 'action', 'reject');
		uci.delete(uciconfig, cfg['.name'], 'outbound');
	} else if (!cfg.action) {
		uci.set(uciconfig, cfg['.name'], 'action', 'route');
	}
});

uci.foreach(uciconfig, uciapprule, (cfg) => {
	if (!isEmpty(cfg.custom_name))
		uci.delete(uciconfig, cfg['.name'], 'custom_name');
});

const current_proxy_mode = uci.get(uciconfig, ucimain, 'proxy_mode');
if (current_proxy_mode === 'redirect_tun' || current_proxy_mode === 'redirect_tproxy')
	uci.set(uciconfig, ucimain, 'proxy_mode', 'tun');

const current_routing_mode = uci.get(uciconfig, ucimain, 'routing_mode');
if (current_routing_mode === 'gfwlist' || current_routing_mode === 'proxy_mainland_china')
	uci.set(uciconfig, ucimain, 'routing_mode', 'bypass_mainland_china');

const auto_firewall = uci.get(uciconfig, uciserver, 'auto_firewall');
if (!isEmpty(auto_firewall))
	uci.delete(uciconfig, uciserver, 'auto_firewall');

uci.foreach(uciconfig, uciserver, (cfg) => {
	if (auto_firewall === '1')
		uci.set(uciconfig, cfg['.name'], 'firewall' , '1');

	if (!isEmpty(cfg.sniff_override))
		uci.delete(uciconfig, cfg['.name'], 'sniff_override');

	if (!isEmpty(cfg.domain_strategy))
		uci.delete(uciconfig, cfg['.name'], 'domain_strategy');
});

if (!isEmpty(uci.changes(uciconfig)))
	uci.commit(uciconfig);
