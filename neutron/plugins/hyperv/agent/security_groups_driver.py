#Copyright 2014 Cloudbase Solutions SRL
#All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron.agent import firewall
from neutron.openstack.common import log as logging
from neutron.plugins.hyperv.agent import utilsfactory
from neutron.plugins.hyperv.agent import utilsv2

LOG = logging.getLogger(__name__)


_ACL_PROP_MAP = {
    'direction': {'ingress': utilsv2.HyperVUtilsV2._ACL_DIR_IN,
                  'egress': utilsv2.HyperVUtilsV2._ACL_DIR_OUT},
    'ethertype': {'IPv4': utilsv2.HyperVUtilsV2._ACL_TYPE_IPV4,
                  'IPv6': utilsv2.HyperVUtilsV2._ACL_TYPE_IPV6},
    'protocol': {'tcp': utilsv2.HyperVUtilsV2._TCP_PROTOCOL,
                 'udp': utilsv2.HyperVUtilsV2._UDP_PROTOCOL,
                 'icmp': utilsv2.HyperVUtilsV2._ICMP_PROTOCOL},
    'action': {'allow': utilsv2.HyperVUtilsV2._ACL_ACTION_ALLOW,
               'deny': utilsv2.HyperVUtilsV2._ACL_ACTION_DENY},
    'default': "ANY",
    'address_default': {'IPv4': '0.0.0.0/0', 'IPv6': '::/0'}
}


class HyperVSecurityGroupsDriver(firewall.FirewallDriver):
    """Security Groups Driver.

    Security Groups implementation for Hyper-V VMs.
    """

    def __init__(self):
        self._utils = utilsfactory.get_hypervutils()
        self._sg_gen = utilsfactory.get_class(SecurityGroupRuleGenerator,
                                              SecurityGroupRuleGeneratorR2)
        self._sec_group_rules = {}
        self._security_ports = {}

    def prepare_port_filter(self, port):
        LOG.debug('Creating port %s rules' % len(port['security_group_rules']))

        # newly created port, add default rules.
        if port['device'] not in self._security_ports:
            LOG.debug('Creating default reject rules.')
            self._utils.remove_all_security_rules(port['id'])
            self._sec_group_rules[port['id']] = []

            def_sg_rules = self._sg_gen.create_default_sg_rules()
            self._add_sg_port_rules(port['id'], def_sg_rules)

        self._security_ports[port['device']] = port
        self._create_port_rules(port['id'], port['security_group_rules'])

    def _create_port_rules(self, port_id, rules):
        sg_rules = self._sg_gen.create_security_group_rules(rules)
        old_sg_rules = self._sec_group_rules[port_id]
        add, rm = self._sg_gen.compute_new_rules_add(old_sg_rules, sg_rules)

        self._remove_sg_port_rules(port_id, list(set(rm)))
        self._add_sg_port_rules(port_id, list(set(add)))

    def _remove_port_rules(self, port_id, rules):
        sg_rules = self._sg_gen.create_security_group_rules(rules)
        self._remove_sg_port_rules(port_id, list(set(sg_rules)))

    def _add_sg_port_rules(self, port_id, sg_rules):
        old_sg_rules = self._sec_group_rules[port_id]
        for rule in sg_rules:
            try:
                self._utils.create_security_rule(port_id, rule)
                old_sg_rules.append(rule)
            except Exception as ex:
                LOG.error(_('Hyper-V Exception: %(hyperv_exeption)s while '
                            'adding rule: %(rule)s'),
                          dict(hyperv_exeption=ex, rule=rule))

    def _remove_sg_port_rules(self, port_id, sg_rules):
        old_sg_rules = self._sec_group_rules[port_id]
        for rule in sg_rules:
            try:
                self._utils.remove_security_rule(port_id, rule)
                old_sg_rules.remove(rule)
            except Exception as ex:
                LOG.error(_('Hyper-V Exception: %(hyperv_exeption)s while '
                            'removing rule: %(rule)s'),
                          dict(hyperv_exeption=ex, rule=rule))

    def apply_port_filter(self, port):
        LOG.info(_('Aplying port filter.'))

    def update_port_filter(self, port):
        LOG.info(_('Updating port rules.'))

        if port['device'] not in self._security_ports:
            self.prepare_port_filter(port)
            return

        old_port = self._security_ports[port['device']]
        rules = old_port['security_group_rules']
        param_port_rules = port['security_group_rules']

        new_rules = [r for r in param_port_rules if r not in rules]
        remove_rules = [r for r in rules if r not in param_port_rules]

        LOG.info(_("Creating %(new)s new rules, removing %(old)s "
                   "old rules."),
                 {'new': len(new_rules),
                  'old': len(remove_rules)})

        self._remove_port_rules(old_port['id'], remove_rules)
        self._create_port_rules(port['id'], new_rules)

        self._security_ports[port['device']] = port

    def remove_port_filter(self, port):
        LOG.info(_('Removing port filter'))
        self._security_ports.pop(port['device'], None)
        self._sec_group_rules.pop(port['id'], None)

    @property
    def ports(self):
        return self._security_ports


class SecurityGroupRuleGenerator(object):

    def create_security_group_rules(self, rules):
        security_group_rules = []
        for rule in rules:
            security_group_rules.extend(self.create_security_group_rule(rule))
        return security_group_rules

    def create_security_group_rule(self, rule):
        # TODO(claudiub): return [] instead, if rule contains ports?
        acl_type = _ACL_PROP_MAP['ethertype'][rule['ethertype']]
        direction = _ACL_PROP_MAP['direction'][rule['direction']]
        remote_address = self._get_rule_remote_address(rule)

        return [SecurityGroupRule(acl_type=acl_type,
                                  direction=direction,
                                  remote_addr=remote_address)]

    def create_default_sg_rules(self):
        ip_type_pairs = [(_ACL_PROP_MAP['ethertype'][ip],
                          _ACL_PROP_MAP['address_default'][ip])
                         for ip in _ACL_PROP_MAP['ethertype'].keys()]

        action = _ACL_PROP_MAP['action']['deny']
        sg_rules = []
        for direction in _ACL_PROP_MAP['direction'].values():
            for acl_type, address in ip_type_pairs:
                sg_rules.append(SecurityGroupRule(acl_type=acl_type,
                                                  direction=direction,
                                                  remote_addr=address,
                                                  action=action))
        return sg_rules

    def compute_new_rules_add(self, old_rules, new_rules):
        add_rules = [r for r in new_rules if r not in old_rules]
        deny_rules = [r for r in old_rules
                      if r.Action == _ACL_PROP_MAP['action']['deny']]

        remove_rules = []
        for new_rule in add_rules:
            for old_rule in deny_rules:
                if new_rule.AclType == old_rule.AclType:
                    remove_rules.append(old_rule)

        return add_rules, remove_rules

    def _get_rule_remote_address(self, rule):
        if rule['direction'] is 'ingress':
            ip_prefix = 'source_ip_prefix'
        else:
            ip_prefix = 'dest_ip_prefix'

        if ip_prefix in rule:
            return rule[ip_prefix]
        return _ACL_PROP_MAP['address_default'][rule['ethertype']]


class SecurityGroupRuleGeneratorR2(SecurityGroupRuleGenerator):

    def create_security_group_rule(self, rule):
        local_port = self._get_rule_port_range(rule)
        direction = _ACL_PROP_MAP['direction'][rule['direction']]
        remote_address = self._get_rule_remote_address(rule)
        protocol = self._get_rule_protocol(rule)
        if protocol == _ACL_PROP_MAP['default']:
            # ANY protocols must be split up, to make stateful rules.
            protocols = _ACL_PROP_MAP['protocol'].values()
        else:
            protocols = [protocol]

        sg_rules = [SecurityGroupRuleR2(direction=direction,
                                        local_port=local_port,
                                        protocol=proto,
                                        remote_addr=remote_address)
                    for proto in protocols]

        if (direction == _ACL_PROP_MAP['direction']["egress"] and
                protocol == _ACL_PROP_MAP['default']):
            # ICMP rules cannot be set as stateful. Create an Inbound
            # equivalent rule, so PING REPLY can be accepted.
            sg_rules.append(SecurityGroupRuleR2(
                direction=_ACL_PROP_MAP['direction']['ingress'],
                local_port='',
                protocol=_ACL_PROP_MAP['protocol']['icmp'],
                remote_addr=remote_address))
        elif protocol == _ACL_PROP_MAP['protocol']['icmp']:
            # If ICMP rule is added in one direction, create an equivalent
            # rule for the other direction.
            if direction == _ACL_PROP_MAP['direction']['ingress']:
                direction = _ACL_PROP_MAP['direction']['egress']
            else:
                direction = _ACL_PROP_MAP['direction']['ingress']
            sg_rules.append(SecurityGroupRuleR2(
                direction=direction,
                local_port='',
                protocol=protocol,
                remote_addr=remote_address))

        return sg_rules

    def create_default_sg_rules(self):
        ip_type_pairs = [(_ACL_PROP_MAP['ethertype'][ip],
                          _ACL_PROP_MAP['address_default'][ip])
                         for ip in _ACL_PROP_MAP['ethertype'].keys()]

        action = _ACL_PROP_MAP['action']['deny']
        port = _ACL_PROP_MAP['default']
        sg_rules = []
        for direction in _ACL_PROP_MAP['direction'].values():
            for protocol in _ACL_PROP_MAP['protocol'].values():
                for acl_type, address in ip_type_pairs:
                    sg_rules.append(SecurityGroupRuleR2(direction=direction,
                                                        local_port=port,
                                                        protocol=protocol,
                                                        remote_addr=address,
                                                        action=action))
        return sg_rules

    def compute_new_rules_add(self, old_rules, new_rules):
        add_rules = [r for r in new_rules if r not in old_rules]
        return add_rules, []

    def _get_rule_port_range(self, rule):
        if 'port_range_min' in rule and 'port_range_max' in rule:
            return '%s-%s' % (rule['port_range_min'],
                              rule['port_range_max'])
        return _ACL_PROP_MAP['default']

    def _get_rule_protocol(self, rule):
        protocol = self._get_rule_prop_or_default(rule, 'protocol')
        if protocol in _ACL_PROP_MAP['protocol'].keys():
            return _ACL_PROP_MAP['protocol'][protocol]

        return protocol

    def _get_rule_prop_or_default(self, rule, prop):
        if prop in rule:
            return rule[prop]
        return _ACL_PROP_MAP['default']


class SecurityGroupRuleBase(object):

    _FIELDS = []

    def __eq__(self, obj):
        for f in self._FIELDS:
            if not hasattr(obj, f) or getattr(obj, f) != getattr(self, f):
                return False
        return True

    def __str__(self):
        return str(self.to_dict())

    def __repr(self):
        return str(self)

    def to_dict(self):
        return dict((field, getattr(self, field)) for field in self._FIELDS)


class SecurityGroupRule(SecurityGroupRuleBase):

    _FIELDS = ["AclType", "Action", "Direction", "Applicability",
               "RemoteAddress", "RemoteAddressPrefixLength"]

    Applicability = utilsv2.HyperVUtilsV2._ACL_APPLICABILITY_REMOTE

    def __init__(self, acl_type, direction, remote_addr,
                 action=_ACL_PROP_MAP['action']['allow']):
        remote_address, prefix_len = remote_addr.split('/')
        self.AclType = acl_type
        self.Direction = direction
        self.Action = action
        self.RemoteAddress = remote_address
        self.RemoteAddressPrefixLength = int(prefix_len)


class SecurityGroupRuleR2(SecurityGroupRuleBase):

    _FIELDS = ["Direction", "Action", "LocalPort", "Protocol",
               "RemoteIPAddress", "Stateful", "IdleSessionTimeout"]

    IdleSessionTimeout = 0

    def __init__(self, direction, local_port, protocol, remote_addr,
                 action=_ACL_PROP_MAP['action']['allow']):
        is_not_icmp = protocol is not _ACL_PROP_MAP['protocol']['icmp']

        self.Direction = direction
        self.Action = action
        self.LocalPort = str(local_port) if is_not_icmp else ''
        self.Protocol = protocol
        self.RemoteIPAddress = remote_addr
        self.Stateful = (is_not_icmp and
                         action is not _ACL_PROP_MAP['action']['deny'])

    def __lt__(self, obj):
        return self.Protocol > obj.Protocol
