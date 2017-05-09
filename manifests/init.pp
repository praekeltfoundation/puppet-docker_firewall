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
#   'drop'. Starting with Docker 1.13.0 the default policy set by the daemon is
#   DROP: https://github.com/docker/docker/pull/28257
#
# [*drop_rules*]
#   A hash of firewall resources to create. These rules will apply to the
#   DOCKER_INPUT chain and drop connections.
#
# [*accept_rules*]
#   A hash of firewall resources to create. These rules will apply to the
#   DOCKER_INPUT chain and return to the DOCKER chain so the connection is
#   accepted if it is really headed for a container. NOTE that the default is
#   to accept all connections and without a corresponding drop rule, accept
#   rules do nothing.
class docker_firewall (
  Boolean                        $manage_nat_table             = false,
  Variant[String, Array[String]] $prerouting_nat_purge_ignore  = [],
  Optional[String]               $prerouting_nat_policy        = undef,
  Variant[String, Array[String]] $output_nat_purge_ignore      = [],
  Optional[String]               $output_nat_policy            = undef,
  Variant[String, Array[String]] $postrouting_nat_purge_ignore = [],
  Optional[String]               $postrouting_nat_policy       = undef,

  Boolean                        $manage_filter_table          = false,
  Variant[String, Array[String]] $forward_filter_purge_ignore  = [],
  Optional[String]               $forward_filter_policy        = 'drop',

  Hash[String, Hash] $bridges                                  = {},
  Hash[String, Hash] $default_bridges                          = {'docker0' => {}},

  Hash[String, Hash] $drop_rules                               = {},
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

  # We need to add rules to the start of the DOCKER chain in order to filter
  # incoming connections to all containers. We send packets through our custom
  # DOCKER_INPUT chain for filtering, as we can't manage rules in the DOCKER
  # chain with `firewall` resources, making adding multiple rules a bit tricky.
  # In the DOCKER_INPUT chain, we add rules to DROP packets, as described in
  # this Docker documentation (that might change at any time):
  # https://docs.docker.com/engine/userguide/networking/default_network/container-communication/#communicating-to-the-outside-world

  # This is, unfortunately, different from the usual "whitelist" approach where
  # packets are dropped *by default* and rules are added to allow selective
  # access. This is a "blacklist" approach, which is incovenient but works best
  # with the existing iptables rules that the Docker daemon sets up.

  # This is a bit of a hack to inject our rule into the start of the DOCKER
  # chain. It is necessary for a few reasons:
  # 1. Docker will only append to this chain as containers are launched but it
  #    will flush the chain on daemon restarts. This means our rule needs to be
  #    inserted after Docker starts.
  # 2. The Puppet firewall module can only insert/order rules relative to its
  #    own rules. It can't insert a rule into the start of an arbitrary chain
  #    with other rules in it.
  exec { 'inject iptables rule to jump from DOCKER to DOCKER_INPUT chain':
    # Try delete the chain in case it exists but is in the wrong place, then
    # insert the rule at the start of the chain.
    command => 'iptables -D DOCKER -j DOCKER_INPUT; iptables -I DOCKER -j DOCKER_INPUT',
    # [ (test), iptables, and grep locations, respectively
    path    => ['/usr/bin', '/sbin', '/bin'],
    # Check the rule is present as the first rule in the chain
    unless  => "[ \"$(iptables -S DOCKER | grep -m1 '^-A')\" = '-A DOCKER -j DOCKER_INPUT' ]",
    require => [
      Firewallchain['DOCKER:filter:IPv4'],
      Firewallchain['DOCKER_INPUT:filter:IPv4'],
    ],
  }

  $drop_rules.each |$title, $params| {
    firewall { $title:
      table  => 'filter',
      chain  => 'DOCKER_INPUT',
      action => 'drop',
      *      => $params,
    }
  }

  $accept_rules.each |$title, $params| {
    firewall { $title:
      table  => 'filter',
      chain  => 'DOCKER_INPUT',
      action => 'return',
      *      => $params,
    }
  }

  $all_bridges = merge($default_bridges, $bridges)
  create_resources(docker_firewall::bridge, $all_bridges)
}
