# == Class: docker_firewall
#
# Manages Docker firewall (iptables) rules. This class keeps a few of the
# standard Docker iptables rules and rewrites a few of the others to prevent
# access to Docker containers from the outside world.
#
# Many of these firewall rules were adapted from:
# https://github.com/hesco/hesco-weave/blob/v0.8.7/manifests/firewall/docker.pp
#
# === Parameters
#
# [*bridges*]
#   A hash of additional Docker network interfaces to set up firewall rules for.
#   Rules will be set up for interfaces with these names as well as the
#   interfaces listed in the *default_bridges* parameter.
#
# [*default_bridges*]
#   The default Docker network interfaces to set up firewall rules for.
#   Generally, you should only need to adjust the *bridges* parameter. By
#   default this just includes the 'docker0' bridge interface.
#
# [*prerouting_nat_purge_ignore*]
#   A list of regexes to use when purging the PREROUTING chain in the nat table.
#   Rules that match one or more of the regexes will not be deleted.
#
# [*prerouting_nat_policy*]
#   The default policy for the PREROUTING chain in the nat table.
#
# [*output_nat_purge_ignore*]
#   A list of regexes to use when purging the OUTPUT chain in the nat table.
#   Rules that match one or more of the regexes will not be deleted.
#
# [*output_nat_policy*]
#   The default policy for the OUTPUT chain in the nat table.
#
# [*postrouting_nat_purge_ignore*]
#   A list of regexes to use when purging the POSTROUTING chain in the nat
#   table. Rules that match one or more of the regexes will not be deleted.
#
# [*output_nat_policy*]
#   The default policy for the POSTROUTING chain in the nat table. The default
#   is 'drop'.
#
# [*forward_filter_purge_ignore*]
#   A list of regexes to use when purging the OUTPUT chain in the nat table.
#   Rules that match one or more of the regexes will not be deleted.
#
# [*output_nat_policy*]
#   The default policy for the OUTPUT chain in the nat table.
#
# [*accept_eth0*]
#   Whether or not to accept connections to Docker containers from the eth0
#   interface.
#
# [*accept_eth1*]
#   Whether or not to accept connections to Docker containers from the eth1
#   interface.
#
# [*accept_rules*]
#   A hash of firewall resources to create. These rules will apply to the
#   DOCKER_INPUT chain and jump to the DOCKER chain so the connection is
#   accepted if it is really headed for a container. All other parameters for
#   the firewall resource can be set by the user.
class docker_firewall (
  Hash[String, Hash] $bridges                      = {},
  Hash[String, Hash] $default_bridges              = {'docker0' => {}},

  Variant[String, Array[String]] $prerouting_nat_purge_ignore  = [],
  Optional[String]               $prerouting_nat_policy        = undef,
  Variant[String, Array[String]] $output_nat_purge_ignore      = [],
  Optional[String]               $output_nat_policy            = undef,
  Variant[String, Array[String]] $postrouting_nat_purge_ignore = [],
  Optional[String]               $postrouting_nat_policy       = undef,
  Variant[String, Array[String]] $forward_filter_purge_ignore  = [],
  Optional[String]               $forward_filter_policy        = 'drop',

  Boolean            $accept_eth0  = false,
  Boolean            $accept_eth1  = false,
  Hash[String, Hash] $accept_rules = {},
) {
  include firewall

  # nat table
  # =========

  # PREROUTING
  firewallchain { 'PREROUTING:nat:IPv4':
    ensure => present,
    purge  => true,
    ignore => $prerouting_nat_purge_ignore,
    policy => $prerouting_nat_policy,
  }
  # -A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
  firewall { '100 DOCKER table PREROUTING LOCAL traffic':
    table    => 'nat',
    chain    => 'PREROUTING',
    dst_type => 'LOCAL',
    proto    => 'all',
    jump     => 'DOCKER',
  }

  # OUTPUT
  firewallchain { 'OUTPUT:nat:IPv4':
    ensure => present,
    purge  => true,
    ignore => $output_nat_purge_ignore,
    policy => $output_nat_policy,
  }
  # -A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
  firewall { '100 DOCKER chain, route LOCAL non-loopback traffic to DOCKER':
    table       => 'nat',
    chain       => 'OUTPUT',
    destination => "! ${::network_lo}/8",
    dst_type    => 'LOCAL',
    proto       => 'all',
    jump        => 'DOCKER',
  }

  # POSTROUTING
  # Docker dynamically adds masquerade rules per container. These are difficult
  # to match on accurately. This regex matches a POSTROUTING rule with identical
  # source (-s) and destination IPv4 addresses (-d), plus some other parameters
  # (likely to be a match on the TCP or UDP port), that jumps to the MASQUERADE
  # action.
  $default_postrouting_nat_purge_ignore = [
    '^-A POSTROUTING -s (?<source>(?:[0-9]{1,3}\.){3}[0-9]{1,3})\/32 -d (\g<source>)\/32 .* -j MASQUERADE$',
  ]
  $_postrouting_nat_purge_ignore = $postrouting_nat_purge_ignore ? {
    String => [$postrouting_nat_purge_ignore],
    Array  => $postrouting_nat_purge_ignore,
  }
  $final_postrouting_nat_purge_ignore = concat($default_postrouting_nat_purge_ignore, $_postrouting_nat_purge_ignore)
  firewallchain { 'POSTROUTING:nat:IPv4':
    ensure => present,
    purge  => true,
    ignore => $final_postrouting_nat_purge_ignore,
    policy => $postrouting_nat_policy,
  }

  # DOCKER - let Docker manage this chain completely
  firewallchain { 'DOCKER:nat:IPv4':
    ensure => present,
  }

  # filter table
  # ============

  # FORWARD
  firewallchain { 'FORWARD:filter:IPv4':
    purge  => true,
    ignore => $forward_filter_purge_ignore,
    policy => $forward_filter_policy,
  }

  # The DOCKER-ISOLATION chain is new to Docker 1.10. Its purpose is to isolate
  # different Docker bridge networks. Docker adds a rule as the first rule to
  # the FORWARD chain that sends all traffic through the DOCKER-ISOLATION chain.
  # The DOCKER-ISOLATION chain should only ever contain DROP rules so it should
  # be safe to keep Docker's behaviour with regards to this chain.
  # DOCKER-ISOLATION - let Docker manage this chain completely
  firewallchain { 'DOCKER-ISOLATION:filter:IPv4':
    ensure => present,
  }
  # -A FORWARD -j DOCKER-ISOLATION
  firewall { '100 send FORWARD traffic to DOCKER-ISOLATION chain':
    table => 'filter',
    chain => 'FORWARD',
    proto => 'all',
    jump  => 'DOCKER-ISOLATION',
  }

  # DOCKER - let Docker manage this chain completely
  firewallchain { 'DOCKER:filter:IPv4':
    ensure => present,
  }

  # DOCKER_INPUT
  firewallchain { 'DOCKER_INPUT:filter:IPv4':
    ensure => present,
    purge  => true,
  }

  # This is a way to achieve "default DROP" for incoming traffic to the docker0
  # interface.
  # -A DOCKER_INPUT -j DROP
  firewall { '999 drop DOCKER_INPUT traffic':
    table  => 'filter',
    chain  => 'DOCKER_INPUT',
    proto  => 'all',
    action => 'drop',
  }

  # -A DOCKER_INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  firewall { '100 accept related, established traffic in DOCKER_INPUT chain':
    table   => 'filter',
    chain   => 'DOCKER_INPUT',
    ctstate => ['RELATED', 'ESTABLISHED'],
    proto   => 'all',
    action  => 'accept',
  }

  if $accept_eth0 {
    # -A DOCKER_INPUT -i eth0 -j DOCKER
    firewall { '200 DOCKER chain, DOCKER_INPUT traffic from eth0':
      table   => 'filter',
      chain   => 'DOCKER_INPUT',
      iniface => 'eth0',
      proto   => 'all',
      jump    => 'DOCKER',
    }
  }

  if $accept_eth1 {
    # -A DOCKER_INPUT -i eth1 -j DOCKER
    firewall { '200 DOCKER chain, DOCKER_INPUT traffic from eth1':
      table   => 'filter',
      chain   => 'DOCKER_INPUT',
      iniface => 'eth1',
      proto   => 'all',
      jump    => 'DOCKER',
    }
  }

  $accept_rules.each |$name, $rule| {
    firewall { $name:
      table => 'filter',
      chain => 'DOCKER_INPUT',
      jump  => 'DOCKER',
      *     => $rule,
    }
  }

  $all_bridges = merge($default_bridges, $bridges)
  create_resources(docker_firewall::bridge, $all_bridges)
}
