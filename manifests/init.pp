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
# [*manage_nat_table*]
#   Whether or not to manage the chains that Docker uses in the nat table.
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
# [*postrouting_nat_policy*]
#   The default policy for the POSTROUTING chain in the nat table.
#
# [*manage_filter_table*]
#   Whether or not to manage the chains that Docker uses in the filter table
#   (currently just the FORWARD chain).
#
# [*forward_filter_purge_ignore*]
#   A list of regexes to use when purging the OUTPUT chain in the nat table.
#   Rules that match one or more of the regexes will not be deleted.
#
# [*forward_policy*]
#   The default policy for the FORWARD chain in the filter table. The default is
#   'drop'.
#
# [*accept_rules*]
#   A hash of firewall resources to create. These rules will apply to the
#   DOCKER_INPUT chain and jump to the DOCKER chain so the connection is
#   accepted if it is really headed for a container. All other parameters for
#   the firewall resource can be set by the user.
class docker_firewall (
  Boolean $manage_nat_table                                    = false,
  Variant[String, Array[String]] $prerouting_nat_purge_ignore  = [],
  Optional[String]               $prerouting_nat_policy        = undef,
  Variant[String, Array[String]] $output_nat_purge_ignore      = [],
  Optional[String]               $output_nat_policy            = undef,
  Variant[String, Array[String]] $postrouting_nat_purge_ignore = [],
  Optional[String]               $postrouting_nat_policy       = undef,

  Boolean $manage_filter_table                                 = false,
  Variant[String, Array[String]] $forward_filter_purge_ignore  = [],
  Optional[String]               $forward_filter_policy        = 'drop',

  Hash[String, Hash] $bridges                                  = {},
  Hash[String, Hash] $default_bridges                          = {'docker0' => {}},

  Hash[String, Hash] $accept_rules                             = {},
) {
  include firewall

  if $manage_nat_table {
    include docker_firewall::nat
  }
  if $manage_filter_table {
    include docker_firewall::filter
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
