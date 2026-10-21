"""The firewall configuration: cluster, node and guest options, rules, aliases, IP sets and security groups.

Follows pve-firewall (PVE/API2/Firewall/*.pm, and PVE/Firewall.pm for the rule
fields, `verify_rule` and the digests). Nothing is enforced; the config is kept
and read back. A guest's firewall is kept by VMID whatever the guest is, so
`/nodes/{node}/qemu/{vmid}/firewall` and the `lxc` path share the code (PVE
does not check that the guest exists either).
"""

import copy
import hashlib
import ipaddress
import re
import time

from . import schema as pve_schema
from .routing import StatefulRoutes, check_digest, die, param_error, split_list

NAME_PATTERN = r'[A-Za-z][A-Za-z0-9\-\_]+'
ALIAS_RE = re.compile(r'^(?:dc/|guest/)?' + NAME_PATTERN + r'\Z')
RULE_KEYS = ('type', 'action', 'macro', 'iface', 'source', 'dest', 'proto', 'enable', 'log', 'sport', 'dport',
             'comment', 'icmp-type')
PORT_PROTOCOLS = ('udp', '17', 'udplite', '136', 'tcp', '6', 'dccp', '33', 'sctp', '132')
ENVS = {'cluster': ('in', 'out', 'forward', 'group'), 'host': ('in', 'out', 'forward', 'group'),
        'group': ('in', 'out', 'forward'), 'vm': ('in', 'out', 'group'), 'ct': ('in', 'out', 'group')}
ALLOW_IFACE = {'cluster': True, 'host': True, 'group': False, 'vm': True, 'ct': True}

ICMP_TYPES = set('''any echo-reply destination-unreachable network-unreachable host-unreachable protocol-unreachable
port-unreachable fragmentation-needed source-route-failed network-unknown host-unknown network-prohibited
host-prohibited TOS-network-unreachable TOS-host-unreachable communication-prohibited host-precedence-violation
precedence-cutoff source-quench redirect network-redirect host-redirect TOS-network-redirect TOS-host-redirect
echo-request router-advertisement router-solicitation time-exceeded ttl-zero-during-transit
ttl-zero-during-reassembly parameter-problem ip-header-bad required-option-missing timestamp-request
timestamp-reply address-mask-request address-mask-reply'''.split())
ICMPV6_TYPES = set('''destination-unreachable no-route communication-prohibited beyond-scope address-unreachable
port-unreachable failed-policy reject-route packet-too-big time-exceeded ttl-zero-during-transit
ttl-zero-during-reassembly parameter-problem bad-header unknown-header-type unknown-option echo-request echo-reply
router-solicitation router-advertisement neighbor-solicitation neighbour-solicitation neighbor-advertisement
neighbour-advertisement redirect'''.split())
# A sample of /etc/protocols and /etc/services (PVE reads the whole files).
PROTOCOLS = {'ip': 0, 'icmp': 1, 'igmp': 2, 'ipencap': 4, 'tcp': 6, 'egp': 8, 'udp': 17, 'dccp': 33, 'ipv6': 41,
             'ipv6-route': 43, 'ipv6-frag': 44, 'gre': 47, 'esp': 50, 'ah': 51, 'ipv6-icmp': 58, 'ipv6-nonxt': 59,
             'ipv6-opts': 60, 'ospf': 89, 'ipip': 94, 'pim': 103, 'vrrp': 112, 'l2tp': 115, 'sctp': 132,
             'udplite': 136}
SERVICES = {'echo': 7, 'ftp-data': 20, 'ftp': 21, 'ssh': 22, 'telnet': 23, 'smtp': 25, 'time': 37, 'domain': 53,
            'bootps': 67, 'bootpc': 68, 'tftp': 69, 'http': 80, 'kerberos': 88, 'pop3': 110, 'sunrpc': 111,
            'nntp': 119, 'ntp': 123, 'netbios-ns': 137, 'netbios-dgm': 138, 'netbios-ssn': 139, 'imap2': 143,
            'imap': 143, 'snmp': 161, 'snmp-trap': 162, 'bgp': 179, 'ldap': 389, 'https': 443,
            'microsoft-ds': 445, 'submission': 587, 'ldaps': 636, 'syslog': 514, 'imaps': 993, 'pop3s': 995,
            'openvpn': 1194, 'ms-sql-s': 1433, 'nfs': 2049, 'mysql': 3306, 'postgresql': 5432, 'vnc': 5900,
            'x11': 6000, 'webmin': 10000}
# macro -> description, from PVE::Firewall's $pve_fw_macros.
MACROS = {
    'Amanda': 'Amanda Backup',
    'Auth': 'Auth (identd) traffic',
    'BGP': 'Border Gateway Protocol traffic',
    'BitTorrent': 'BitTorrent traffic for BitTorrent 3.1 and earlier',
    'BitTorrent32': 'BitTorrent traffic for BitTorrent 3.2 and later',
    'Ceph': 'Ceph Storage Cluster traffic (Ceph Monitors, OSD & MDS Daemons)',
    'CVS': 'Concurrent Versions System pserver traffic',
    'Citrix': 'Citrix/ICA traffic (ICA, ICA Browser, CGP)',
    'DAAP': 'Digital Audio Access Protocol traffic (iTunes, Rythmbox daemons)',
    'DCC': 'Distributed Checksum Clearinghouse spam filtering mechanism',
    'DHCPfwd': 'Forwarded DHCP traffic',
    'DNS': 'Domain Name System traffic (upd and tcp)',
    'Distcc': 'Distributed Compiler service',
    'FTP': 'File Transfer Protocol',
    'Finger': 'Finger protocol (RFC 742)',
    'GNUnet': 'GNUnet secure peer-to-peer networking traffic',
    'GRE': 'Generic Routing Encapsulation tunneling protocol',
    'Git': 'Git distributed revision control traffic',
    'HKP': 'OpenPGP HTTP key server protocol traffic',
    'HTTP': 'Hypertext Transfer Protocol (WWW)',
    'HTTPS': 'Hypertext Transfer Protocol (WWW) over SSL',
    'ICPV2': 'Internet Cache Protocol V2 (Squid) traffic',
    'ICQ': 'AOL Instant Messenger traffic',
    'IMAP': 'Internet Message Access Protocol',
    'IMAPS': 'Internet Message Access Protocol over SSL',
    'IPIP': 'IPIP capsulation traffic',
    'IPsec': 'IPsec traffic',
    'IPsecah': 'IPsec authentication (AH) traffic',
    'IPsecnat': 'IPsec traffic and Nat-Traversal',
    'IRC': 'Internet Relay Chat traffic',
    'Jetdirect': 'HP Jetdirect printing',
    'L2TP': 'Layer 2 Tunneling Protocol traffic',
    'LDAP': 'Lightweight Directory Access Protocol traffic',
    'LDAPS': 'Secure Lightweight Directory Access Protocol traffic',
    'MSNP': 'Microsoft Notification Protocol',
    'MSSQL': 'Microsoft SQL Server',
    'Mail': 'Mail traffic (SMTP, SMTPS, Submission)',
    'MDNS': 'Multicast DNS',
    'Munin': 'Munin networked resource monitoring traffic',
    'MySQL': 'MySQL server',
    'NNTP': 'NNTP traffic (Usenet).',
    'NNTPS': 'Encrypted NNTP traffic (Usenet)',
    'NTP': 'Network Time Protocol (ntpd)',
    'OSPF': 'OSPF multicast traffic',
    'OpenVPN': 'OpenVPN traffic',
    'PCA': 'Symantec PCAnywere (tm)',
    'PMG': 'Proxmox Mail Gateway web interface',
    'POP3': 'POP3 traffic',
    'POP3S': 'Encrypted POP3 traffic',
    'PPtP': 'Point-to-Point Tunneling Protocol',
    'Ping': 'ICMP echo request',
    'PostgreSQL': 'PostgreSQL server',
    'Printer': 'Line Printer protocol printing',
    'RDP': 'Microsoft Remote Desktop Protocol traffic',
    'RIP': 'Routing Information Protocol (bidirectional)',
    'RNDC': 'BIND remote management protocol',
    'Razor': 'Razor Antispam System',
    'Rdate': 'Remote time retrieval (rdate)',
    'Rsync': 'Rsync server',
    'SANE': 'SANE network scanning',
    'SMB': 'Microsoft SMB traffic',
    'SMBswat': 'Samba Web Administration Tool',
    'SMTP': 'Simple Mail Transfer Protocol',
    'SMTPS': 'Encrypted Simple Mail Transfer Protocol',
    'SNMP': 'Simple Network Management Protocol',
    'SPAMD': 'Spam Assassin SPAMD traffic',
    'SSH': 'Secure shell traffic',
    'SVN': 'Subversion server (svnserve)',
    'SixXS': 'SixXS IPv6 Deployment and Tunnel Broker',
    'SPICEproxy': 'Proxmox VE SPICE display proxy traffic',
    'Squid': 'Squid web proxy traffic',
    'Submission': 'Mail message submission traffic',
    'Syslog': 'Syslog protocol (RFC 5424) traffic',
    'TFTP': 'Trivial File Transfer Protocol traffic',
    'Telnet': 'Telnet traffic',
    'Telnets': 'Telnet over SSL',
    'Time': 'RFC 868 Time protocol',
    'Trcrt': 'Traceroute (for up to 30 hops) traffic',
    'VNC': 'VNC traffic for VNC displays 0 - 99',
    'VNCL': 'VNC traffic from Vncservers to Vncviewers in listen mode',
    'Web': 'WWW traffic (HTTP and HTTPS)',
    'Webcache': 'Web Cache/Proxy traffic (port 8080)',
    'Webmin': 'Webmin traffic',
    'Whois': 'Whois (nicname, RFC 3912) traffic',
}
MACRO_NAMES = dict((name.lower(), name) for name in MACROS)


def empty_conf():
    return {'options': {}, 'rules': [], 'aliases': {}, 'ipset': {}, 'ipset_comments': {}, 'groups': {},
            'group_comments': {}}


# --------------------------------------------------------------- digests

def _add(sha, entry):
    for key in sorted(entry):
        value = entry[key]
        if value is not None and not isinstance(value, (dict, list)):
            sha.update('{0}:{1}\n'.format(key, value).encode())


def copy_list_with_digest(entries):
    """PVE::Firewall::copy_list_with_digest: copies of the entries, each with the digest of the whole list."""
    sha = hashlib.sha1()
    out = []
    for entry in entries:
        _add(sha, entry)
        out.append(dict((k, v) for k, v in entry.items() if v is not None))
    digest = sha.hexdigest()
    for entry in out:
        entry['digest'] = digest
    return out, digest


def copy_object_with_digest(obj):
    sha = hashlib.sha1()
    _add(sha, obj)
    digest = sha.hexdigest()
    out = dict((k, v) for k, v in obj.items() if v is not None)
    out['digest'] = digest
    return out, digest


# ------------------------------------------------------------ verification

def _ip(text):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _network(text, strict=False):
    if not re.match(r'^[0-9a-fA-F:.]+/\d+$', text):
        return None
    try:
        return ipaddress.ip_network(text, strict=strict)
    except ValueError:
        return None


def parse_address_list(text):
    """PVE::Firewall::parse_address_list: the IP version (4, 6 or None); ValueError with PVE's message."""
    if re.match(r'^\+\S+\Z', text):
        if len(text) > 65:
            raise ValueError('ipset name too long')
        return None
    if re.match(r'^(?:dc/|guest/)?' + NAME_PATTERN + r'\Z', text):
        if len(text) > 64:
            raise ValueError('alias name too long')
        return None
    if '\n' in text:
        raise ValueError('must not contain newlines')
    elements = text.split(',')
    while elements and elements[-1] == '':
        elements.pop()
    if text != ','.join(elements):
        raise ValueError('extraneous commas in list')
    version = None
    in_range = False
    for count, element in enumerate(elements, 1):
        parts = element.split('-')
        if len(parts) > 2:
            raise ValueError('not a valid ip or ip range')
        if len(parts) == 2:
            in_range = True
        if in_range and count > 1:
            raise ValueError("you can't use a range in a list")
        found = []
        for part in parts:
            addr = _ip(part)
            if addr is None and in_range:
                raise ValueError('element in IP range must be a single IP')
            net = addr or _network(part)
            if net is None:
                raise ValueError('not a valid IP or CIDR: {0}'.format(part))
            if version and net.version != version:
                raise ValueError("detected mixed ipv4/ipv6 addresses in address list '{0}'".format(text))
            version = net.version
            found.append(net)
        if len(parts) == 1 and '/' in element and _network(element, strict=True) is None:
            raise ValueError('invalid IP address: Invalid prefix {0}'.format(element))
        if len(found) == 2 and found[1] < found[0]:
            raise ValueError('invalid IP address: Last IP address is before first IP address')
    return version


def parse_ports(text, icmp_type_ok):
    """PVE::Firewall::parse_port_name_number_or_range: validates; ValueError with PVE's message."""
    if text in (None, ''):
        return
    elements = text.split(',')
    while elements and elements[-1] == '':
        elements.pop()
    if text != ','.join(elements):
        raise ValueError('extraneous commas in list')
    count = 0
    icmp_port = False
    for item in elements:
        found = re.match(r'^(\d+):(\d+)\Z', item)
        if found:
            count += 2
            first, last = int(found.group(1)), int(found.group(2))
            for port in (first, last):
                if port > 65535:
                    raise ValueError("invalid port '{0}'".format(port))
            if first > last:
                raise ValueError("backwards range '{0}:{1}' not allowed, did you mean '{1}:{0}'?".format(first, last))
        elif re.match(r'^\d+\Z', item):
            count += 1
            if int(item) > 65535:
                raise ValueError("invalid port '{0}'".format(item))
        elif icmp_type_ok and (item in ICMP_TYPES or item in ICMPV6_TYPES):
            icmp_port = True
        elif item not in SERVICES:
            raise ValueError("invalid port '{0}'".format(item))
    if icmp_port and count > 0:
        raise ValueError('ICMP ports not allowed in port range')
    if count > 15:
        raise ValueError('too many entries in port list (> 15 numbers)')


# The prefix of an error from a property's registered format, which the API checks as it parses the request.
FORMAT = 'invalid format - '


def verify_protocol(proto):
    if proto not in PROTOCOLS and proto != 'icmpv6' and not (proto.isdigit() and int(proto) in PROTOCOLS.values()):
        raise ValueError("unknown protocol '{0}'".format(proto))


def verify_rule(rule, cluster, conf, env):
    """PVE::Firewall::verify_rule: the first problem is a 400 on the field; sets `ipversion`.

    cluster and conf are the cluster config and the one the rule lives in (the same for cluster rules and
    security groups)."""
    def err(field, message):
        return param_error(**{field: message})
    version = None

    def set_version(new):
        nonlocal version
        if new:
            if version and new != version:
                raise die('detected mixed ipv4/ipv6 addresses in rule')
            version = new

    def check_reference(name):
        value = rule.get(name)
        if not value:
            return
        if value.startswith('+'):
            found = re.match(r'^\+(?:guest/|dc/|sdn/)?(' + NAME_PATTERN + r')$', value)
            if not found:
                raise err(name, "invalid ipset name '{0}'".format(value))
            if found.group(1) not in cluster['ipset'] and found.group(1) not in conf['ipset']:
                raise err(name, "no such ipset '{0}'".format(found.group(1)))
        else:
            found = re.match(r'^(guest/|dc/)?(' + NAME_PATTERN + r')$', value)
            if found:
                scope, alias = found.group(1) or '', found.group(2).lower()
                if alias not in cluster['aliases'] and alias not in conf['aliases']:
                    raise err(name, "no such alias '{0}'".format(value))
                entry = None
                if scope != 'dc/':
                    entry = conf['aliases'].get(alias)
                if scope != 'guest/' and not entry:
                    entry = cluster['aliases'].get(alias)
                set_version((entry or {}).get('ipversion'))

    rtype, action = rule.get('type'), rule.get('action')
    if not rtype:
        raise err('type', 'missing property')
    if not action:
        raise err('action', 'missing property')
    if rtype not in ENVS[env]:
        raise err('type', "invalid rule type '{0}' for rule_env '{1}'".format(rtype, env))
    if rtype in ('in', 'out', 'forward'):
        if rtype == 'forward' and action == 'REJECT':
            raise err('action', 'cannot define REJECT rules on forward chain')
        if action not in ('ACCEPT', 'DROP', 'REJECT'):
            raise err('action', "unknown action '{0}'".format(action))
    elif rtype == 'group':
        if not re.match(r'^' + NAME_PATTERN + r'\Z', action):
            raise err('action', 'invalid characters in security group name')
    if rule.get('iface'):
        if not ALLOW_IFACE[env]:
            raise err('type', 'parameter -i not allowed for this rule type')
        if env in ('vm', 'ct') and not re.match(r'^net(\d+)$', rule['iface']):
            raise err('iface', "value does not match the regex pattern 'net\\d+'")
    if rule.get('macro'):
        preferred = MACRO_NAMES.get(rule['macro'].lower())
        if not preferred:
            raise err('macro', "unknown macro '{0}'".format(rule['macro']))
        rule['macro'] = preferred
    is_icmp = False
    proto = rule.get('proto')
    if proto:
        try:
            verify_protocol(proto)
        except ValueError as e:
            raise err('proto', FORMAT + str(e)) from None
        set_version({'icmp': 4, 'icmpv6': 6, 'ipv6-icmp': 6}.get(proto))
        is_icmp = proto in ('icmp', 'icmpv6', 'ipv6-icmp', '1', '58')
    if rule.get('dport'):
        try:
            parse_ports(rule['dport'], is_icmp)
        except ValueError as e:
            raise err('dport', FORMAT + str(e)) from None
        if not proto:
            raise err('proto', "missing property - 'dport' requires this property")
        if proto not in PORT_PROTOCOLS and not is_icmp:
            raise err('dport', "protocol '{0}' does not support ports".format(proto))
    if rule.get('icmp-type'):
        icmp = rule['icmp-type']
        if not is_icmp:
            raise err('proto', "missing property - 'icmp-type' requires this property")
        if rule.get('dport'):
            raise err('icmp-type', "'icmp-type' cannot be specified together with 'dport'")
        if proto == 'icmp' and icmp not in ICMP_TYPES:
            raise err('icmp-type', "invalid icmp-type '{0}' for proto 'icmp'".format(icmp))
        if proto in ('icmpv6', 'ipv6-icmp') and icmp not in ICMPV6_TYPES:
            raise err('icmp-type', "invalid icmp-type '{0}' for proto '{1}'".format(icmp, proto))
    if rule.get('sport'):
        try:
            parse_ports(rule['sport'], False)
        except ValueError as e:
            raise err('sport', FORMAT + str(e)) from None
        if not proto:
            raise err('proto', "missing property - 'sport' requires this property")
        if proto not in PORT_PROTOCOLS:
            raise err('sport', "protocol '{0}' does not support ports".format(proto))
    for name in ('source', 'dest'):
        if rule.get(name):
            try:
                set_version(parse_address_list(rule[name]))
            except ValueError as e:
                raise err(name, FORMAT + str(e)) from None
            check_reference(name)
    if version:
        rule['ipversion'] = version
    return rule


def clean_cidr(cidr):
    """PVE::Firewall::clean_cidr: host bits dropped."""
    if '/' not in cidr:
        return cidr
    net = _network(cidr)
    return cidr if net is None else '{0}/{1}'.format(net.network_address, net.prefixlen)


# ------------------------------------------------------------------- API

class FirewallApi(StatefulRoutes):
    """Mixin of FakePve: cluster, node and guest firewall."""

    def _fw(self):
        fw = self.__dict__.get('_fw_state')
        if fw is None:
            fw = self.__dict__['_fw_state'] = {'cluster': empty_conf(), 'nodes': {}, 'guests': {}}
        return fw

    def firewall_config(self, scope, node=None, vmid=None):
        """The stored firewall config of 'cluster', a node ('host') or a guest ('vm' or 'ct')."""
        fw = self._fw()
        if scope in ('cluster', 'group'):
            return fw['cluster']
        if scope == 'host':
            return fw['nodes'].setdefault(node, empty_conf())
        return fw['guests'].setdefault(int(vmid), empty_conf())

    def _routes_firewall(self):
        routes = []
        scopes = (('cluster', '/cluster/firewall'), ('host', '/nodes/{node}/firewall'),
                  ('vm', '/nodes/{node}/qemu/{vmid}/firewall'), ('ct', '/nodes/{node}/lxc/{vmid}/firewall'))
        for scope, base in scopes:
            def bind(fn, scope=scope):
                async def call(v, user):
                    return await fn(scope, v, user)
                return call
            routes += [('GET', base + '/options', bind(self._fw_options_get)),
                       ('PUT', base + '/options', bind(self._fw_options_put)),
                       ('GET', base + '/rules', bind(self._fw_rules_get)),
                       ('POST', base + '/rules', bind(self._fw_rule_create)),
                       ('GET', base + '/rules/{pos}', bind(self._fw_rule_get)),
                       ('PUT', base + '/rules/{pos}', bind(self._fw_rule_update)),
                       ('DELETE', base + '/rules/{pos}', bind(self._fw_rule_delete))]
            if scope == 'host':
                continue
            routes += [('GET', base + '/refs', bind(self._fw_refs)),
                       ('GET', base + '/aliases', bind(self._fw_aliases_get)),
                       ('POST', base + '/aliases', bind(self._fw_alias_create)),
                       ('GET', base + '/aliases/{name}', bind(self._fw_alias_read)),
                       ('PUT', base + '/aliases/{name}', bind(self._fw_alias_update)),
                       ('DELETE', base + '/aliases/{name}', bind(self._fw_alias_delete)),
                       ('GET', base + '/ipset', bind(self._fw_ipsets_get)),
                       ('POST', base + '/ipset', bind(self._fw_ipset_create)),
                       ('DELETE', base + '/ipset/{name}', bind(self._fw_ipset_delete)),
                       ('GET', base + '/ipset/{name}', bind(self._fw_ipset_get)),
                       ('POST', base + '/ipset/{name}', bind(self._fw_ip_create)),
                       ('GET', base + '/ipset/{name}/{cidr}', bind(self._fw_ip_read)),
                       ('PUT', base + '/ipset/{name}/{cidr}', bind(self._fw_ip_update)),
                       ('DELETE', base + '/ipset/{name}/{cidr}', bind(self._fw_ip_delete))]
        group = '/cluster/firewall/groups'
        routes += [('GET', '/cluster/firewall/macros', self._fw_macros),
                   ('GET', group, self._fw_groups_get), ('POST', group, self._fw_group_create),
                   ('DELETE', group + '/{group}', self._fw_group_delete)]
        for method, suffix, fn in (('GET', '', self._fw_rules_get), ('POST', '', self._fw_rule_create),
                                   ('GET', '/{pos}', self._fw_rule_get), ('PUT', '/{pos}', self._fw_rule_update),
                                   ('DELETE', '/{pos}', self._fw_rule_delete)):
            def bind_group(fn=fn):
                async def call(v, user):
                    return await fn('group', v, user)
                return call
            routes.append((method, group + '/{group}' + suffix, bind_group()))
        return routes

    # --------------------------------------------------------------- options

    def _option_names(self, scope):
        base = {'cluster': '/cluster/firewall', 'host': '/nodes/{node}/firewall',
                'vm': '/nodes/{node}/qemu/{vmid}/firewall', 'ct': '/nodes/{node}/lxc/{vmid}/firewall'}[scope]
        props = pve_schema.load().paths[base + '/options']['PUT']['parameters']['properties']
        return [k for k in props if k not in ('node', 'vmid', 'delete', 'digest')]

    async def _fw_options_get(self, scope, v, user):
        conf = self.firewall_config(scope, v.get('node'), v.get('vmid'))
        return copy_object_with_digest(conf['options'])[0]

    async def _fw_options_put(self, scope, v, user):
        conf = self.firewall_config(scope, v.get('node'), v.get('vmid'))
        names = self._option_names(scope)
        check_digest(copy_object_with_digest(conf['options'])[1], v.get('digest'))
        options = dict(conf['options'])
        for name in split_list(v.get('delete')):
            if name not in names:
                raise param_error(**{'delete': "no such option '{0}'".format(name)})
            options.pop(name, None)
        enable = v.get('enable')
        if enable is not None:
            # The cluster firewall keeps a time stamp above 1 (a value that "enable" was set at); other levels 0/1.
            v = dict(v, enable=(int(time.time()) if enable > 1 else enable) if scope == 'cluster'
                     else (1 if enable else 0))
        for name in names:
            if v.get(name) is not None:
                options[name] = v[name]
        conf['options'] = options

    # ----------------------------------------------------------------- rules

    def _rules_of(self, scope, v):
        conf = self.firewall_config(scope, v.get('node'), v.get('vmid'))
        if scope == 'group':
            rules = conf['groups'].get(v['group'])
            if rules is None:
                raise die("no such security group '{0}'".format(v['group']))
            return conf, rules
        return conf, conf['rules']

    def _check_rule(self, scope, rule, conf):
        cluster = self.firewall_config('cluster')
        return verify_rule(rule, cluster, conf, scope)

    @staticmethod
    def _copy_rule_data(rule, v):
        for key in RULE_KEYS:
            if v.get(key) is not None:
                if v[key] in ('', '-'):
                    rule.pop(key, None)
                else:
                    rule[key] = v[key]
        return rule

    async def _fw_rules_get(self, scope, v, user):
        rules = copy_list_with_digest(self._rules_of(scope, v)[1])[0]
        for pos, rule in enumerate(rules):
            rule['pos'] = pos
        return rules

    async def _fw_rule_get(self, scope, v, user):
        rules = copy_list_with_digest(self._rules_of(scope, v)[1])[0]
        if v['pos'] >= len(rules):
            raise die('no rule at position {0}'.format(v['pos']))
        return dict(rules[v['pos']], pos=v['pos'])

    async def _fw_rule_create(self, scope, v, user):
        conf, rules = self._rules_of(scope, v)
        rule = self._copy_rule_data({}, v)
        self._check_rule(scope, rule, conf)
        if v.get('enable') is None:
            rule['enable'] = 0
        rules.insert(0, rule)

    @staticmethod
    def _no_rules_file(scope, conf):
        """PVE parses a missing or empty .fw file to `{}`: its `rules` is undef, which update and delete dereference."""
        if scope == 'group':
            return False
        return not any(conf[key] for key in ('rules', 'options', 'aliases', 'ipset', 'groups') if key in conf)

    def _need_rules(self, scope, conf):
        if self._no_rules_file(scope, conf):
            raise die("Can't use an undefined value as an ARRAY reference at "
                      "/usr/share/perl5/PVE/API2/Firewall/Rules.pm line 462.")

    async def _fw_rule_update(self, scope, v, user):
        conf, rules = self._rules_of(scope, v)
        check_digest(copy_list_with_digest(rules)[1], v.get('digest'))
        self._need_rules(scope, conf)
        pos = v['pos']
        if pos >= len(rules):
            raise die('no rule at position {0}'.format(pos))
        moveto = v.get('moveto')
        if moveto is not None and moveto != pos:
            # Plugin: the rule goes in front of the one now at `moveto`, positions counted before the move.
            moved = []
            for index, entry in enumerate(rules):
                if index == pos:
                    continue
                if index == moveto:
                    moved.append(rules[pos])
                moved.append(entry)
            if moveto >= len(rules):
                moved.append(rules[pos])
            rules[:] = moved
            return
        rule = copy.deepcopy(rules[pos])
        self._copy_rule_data(rule, v)
        for name in split_list(v.get('delete')):
            if name not in RULE_KEYS:
                raise param_error(**{'delete': "no such property ('{0}')".format(name)})
            if name in ('type', 'action'):
                raise param_error(**{'delete': "unable to delete required property '{0}'".format(name)})
            rule.pop(name, None)
        rule.pop('ipversion', None)
        self._check_rule(scope, rule, conf)
        rules[pos] = rule

    async def _fw_rule_delete(self, scope, v, user):
        conf, rules = self._rules_of(scope, v)
        check_digest(copy_list_with_digest(rules)[1], v.get('digest'))
        self._need_rules(scope, conf)
        if v['pos'] >= len(rules):
            raise die('no rule at position {0}'.format(v['pos']))
        del rules[v['pos']]

    # --------------------------------------------------------------- aliases

    @staticmethod
    def _alias_list(conf):
        return [conf['aliases'][k] for k in sorted(conf['aliases'])]

    @staticmethod
    def _version_of(cidr):
        found = _ip(cidr.split('/')[0])
        return found.version if found else None

    async def _fw_aliases_get(self, scope, v, user):
        conf = self.firewall_config(scope, v.get('node'), v.get('vmid'))
        return copy_list_with_digest(self._alias_list(conf))[0]

    async def _fw_alias_create(self, scope, v, user):
        conf = self.firewall_config(scope, v.get('node'), v.get('vmid'))
        key = v['name'].lower()
        if key in conf['aliases']:
            raise param_error(name="alias '{0}' already exists".format(v['name']))
        entry = {'name': v['name'], 'cidr': v['cidr'], 'ipversion': self._version_of(v['cidr'])}
        if v.get('comment'):
            entry['comment'] = v['comment']
        conf['aliases'][key] = entry

    async def _fw_alias_read(self, scope, v, user):
        conf = self.firewall_config(scope, v.get('node'), v.get('vmid'))
        entry = conf['aliases'].get(v['name'].lower())
        if entry is None:
            raise param_error(name='no such alias')
        return dict(entry)

    async def _fw_alias_update(self, scope, v, user):
        conf = self.firewall_config(scope, v.get('node'), v.get('vmid'))
        check_digest(copy_list_with_digest(self._alias_list(conf))[1], v.get('digest'))
        key = v['name'].lower()
        if key not in conf['aliases']:
            raise param_error(name='no such alias')
        entry = {'name': v['name'], 'cidr': v['cidr'], 'ipversion': self._version_of(v['cidr'])}
        if v.get('comment'):
            entry['comment'] = v['comment']
        conf['aliases'][key] = entry
        rename = (v.get('rename') or '').lower()
        if rename and key != rename:
            if rename in conf['aliases']:
                raise param_error(name="alias '{0}' already exists".format(v['rename']))
            entry['name'] = v['rename']
            conf['aliases'][rename] = conf['aliases'].pop(key)

    async def _fw_alias_delete(self, scope, v, user):
        conf = self.firewall_config(scope, v.get('node'), v.get('vmid'))
        check_digest(copy_list_with_digest(self._alias_list(conf))[1], v.get('digest'))
        conf['aliases'].pop(v['name'].lower(), None)

    # ------------------------------------------------------------------ ipset

    @staticmethod
    def _ipset_index(conf):
        entries = [dict(name=name, **({'comment': conf['ipset_comments'][name]}
                                      if conf['ipset_comments'].get(name) else {})) for name in sorted(conf['ipset'])]
        return copy_list_with_digest(entries)

    async def _fw_ipsets_get(self, scope, v, user):
        return self._ipset_index(self.firewall_config(scope, v.get('node'), v.get('vmid')))[0]

    async def _fw_ipset_create(self, scope, v, user):
        conf = self.firewall_config(scope, v.get('node'), v.get('vmid'))
        name, rename = v['name'], v.get('rename')
        if rename:
            check_digest(self._ipset_index(conf)[1], v.get('digest'))
            if rename not in conf['ipset']:
                raise param_error(name="IPSet '{0}' does not exist".format(rename))
            if name in conf['ipset'] and name != rename:
                raise param_error(name="IPSet '{0}' does already exist".format(name))
            conf['ipset'][name] = conf['ipset'].pop(rename)
            comment = conf['ipset_comments'].pop(rename, None)
            if comment:
                conf['ipset_comments'][name] = comment
            if v.get('comment') is not None:
                conf['ipset_comments'][name] = v['comment']
        else:
            if name in conf['ipset']:
                raise param_error(name="IPSet '{0}' already exists".format(name))
            conf['ipset'][name] = []
            if v.get('comment') is not None:
                conf['ipset_comments'][name] = v['comment']

    @staticmethod
    def _ipset_of(conf, name):
        entries = conf['ipset'].get(name)
        if entries is None:
            raise die("no such IPSet '{0}'".format(name))
        return entries

    async def _fw_ipset_delete(self, scope, v, user):
        conf = self.firewall_config(scope, v.get('node'), v.get('vmid'))
        entries = self._ipset_of(conf, v['name'])
        if entries and not v.get('force'):
            raise die("IPSet '{0}' is not empty".format(v['name']))
        del conf['ipset'][v['name']]
        conf['ipset_comments'].pop(v['name'], None)

    async def _fw_ipset_get(self, scope, v, user):
        conf = self.firewall_config(scope, v.get('node'), v.get('vmid'))
        return copy_list_with_digest(self._ipset_of(conf, v['name']))[0]

    def _resolve_alias(self, conf, name):
        """Resolve_alias for an ipset entry: the alias's cidr, or die."""
        found = re.match(r'^(dc/|guest/)?(' + NAME_PATTERN + r')$', name)
        scope, alias = found.group(1) or '', found.group(2).lower()
        entry = None
        if scope != 'dc/' and conf is not self.firewall_config('cluster'):
            entry = conf['aliases'].get(alias)
        if scope != 'guest/' and not entry:
            entry = self.firewall_config('cluster')['aliases'].get(alias)
        if not entry:
            raise die("no such alias '{0}'".format(found.group(2)))
        return entry['cidr']

    async def _fw_ip_create(self, scope, v, user):
        conf = self.firewall_config(scope, v.get('node'), v.get('vmid'))
        entries = self._ipset_of(conf, v['name'])
        cidr = v['cidr']
        if re.match(r'^(?:dc/|guest/)?' + NAME_PATTERN + r'$', cidr):
            if re.search(r'/0+$', self._resolve_alias(conf, cidr)):
                raise param_error(cidr='a zero prefix alias is not allowed in ipset entries')
        else:
            cidr = clean_cidr(cidr)
            cidr = re.sub(r'/128$', '', cidr) if ':' in cidr else re.sub(r'/32$', '', cidr)
        if any(entry['cidr'] == cidr for entry in entries):
            raise param_error(cidr="address '{0}' already exists".format(cidr))
        if re.search(r'/0+$', cidr):
            raise param_error(cidr='a zero prefix is not allowed in ipset entries')
        entry = {'cidr': cidr}
        if v.get('nomatch'):
            entry['nomatch'] = 1
        if v.get('comment'):
            entry['comment'] = v['comment']
        entries.insert(0, entry)

    async def _fw_ip_read(self, scope, v, user):
        conf = self.firewall_config(scope, v.get('node'), v.get('vmid'))
        for entry in copy_list_with_digest(self._ipset_of(conf, v['name']))[0]:
            if entry['cidr'] == v['cidr']:
                return entry
        raise param_error(cidr='no such IP/Network')

    async def _fw_ip_update(self, scope, v, user):
        conf = self.firewall_config(scope, v.get('node'), v.get('vmid'))
        entries = self._ipset_of(conf, v['name'])
        check_digest(copy_list_with_digest(entries)[1], v.get('digest'))
        for entry in entries:
            if entry['cidr'] == v['cidr']:
                entry['nomatch'] = v.get('nomatch')
                entry['comment'] = v.get('comment')
                return
        raise param_error(cidr='no such IP/Network')

    async def _fw_ip_delete(self, scope, v, user):
        conf = self.firewall_config(scope, v.get('node'), v.get('vmid'))
        entries = self._ipset_of(conf, v['name'])
        check_digest(copy_list_with_digest(entries)[1], v.get('digest'))
        entries[:] = [entry for entry in entries if entry['cidr'] != v['cidr']]

    # ------------------------------------------------------------ groups, refs

    async def _fw_macros(self, v, user):
        return [{'macro': name, 'descr': descr} for name, descr in sorted(MACROS.items())]

    @staticmethod
    def _group_index(conf):
        entries = [dict(group=name, **({'comment': conf['group_comments'][name]}
                                       if conf['group_comments'].get(name) else {})) for name in sorted(conf['groups'])]
        return copy_list_with_digest(entries)

    async def _fw_groups_get(self, v, user):
        return self._group_index(self.firewall_config('cluster'))[0]

    def _rename_in_rules(self, old, new):
        fw = self._fw()
        confs = [fw['cluster']] + list(fw['nodes'].values()) + list(fw['guests'].values())
        for conf in confs:
            for rule in conf['rules']:
                if rule.get('type') == 'group' and rule.get('action') == old:
                    rule['action'] = new

    async def _fw_group_create(self, v, user):
        conf = self.firewall_config('cluster')
        group, rename, comment = v['group'], v.get('rename'), v.get('comment')
        if rename:
            check_digest(self._group_index(conf)[1], v.get('digest'))
            if rename not in conf['groups']:
                raise param_error(group="Security group '{0}' does not exist".format(rename))
            if group in conf['groups'] and group != rename:
                raise param_error(group="Security group '{0}' does already exist".format(group))
            if rename == group:
                if comment is not None:
                    conf['group_comments'][rename] = comment
                return
            conf['groups'][group] = conf['groups'][rename]
            moved = conf['group_comments'].get(rename)
            if moved is not None:
                conf['group_comments'][group] = moved
            if comment is not None:
                conf['group_comments'][group] = comment
            self._rename_in_rules(rename, group)
            del conf['groups'][rename]
            conf['group_comments'].pop(rename, None)
        else:
            if group in conf['groups']:
                raise param_error(group="Security group '{0}' already exists".format(group))
            conf['groups'][group] = []
            if comment is not None:
                conf['group_comments'][group] = comment

    async def _fw_group_delete(self, v, user):
        conf = self.firewall_config('cluster')
        rules = conf['groups'].get(v['group'])
        if rules is None:
            raise die("no such security group '{0}'".format(v['group']))
        if rules:
            raise die("Security group '{0}' is not empty".format(v['group']))
        del conf['groups'][v['group']]
        conf['group_comments'].pop(v['group'], None)

    @staticmethod
    def _refs(conf, scope, kind):
        out = []
        if kind in (None, 'ipset'):
            for name in sorted(conf['ipset']):
                item = {'type': 'ipset', 'name': name, 'ref': '+' + name, 'scope': scope}
                if conf['ipset_comments'].get(name):
                    item['comment'] = conf['ipset_comments'][name]
                out.append(item)
        if kind in (None, 'alias'):
            for name in sorted(conf['aliases']):
                item = {'type': 'alias', 'name': name, 'ref': name, 'scope': scope}
                if conf['aliases'][name].get('comment'):
                    item['comment'] = conf['aliases'][name]['comment']
                out.append(item)
        return out

    async def _fw_refs(self, scope, v, user):
        kind = v.get('type')
        out = self._refs(self.firewall_config('cluster'), 'dc', kind)
        if scope != 'cluster':
            out += self._refs(self.firewall_config(scope, v.get('node'), v.get('vmid')), 'guest', kind)
        return out

