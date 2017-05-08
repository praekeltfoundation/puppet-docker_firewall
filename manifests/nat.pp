# == Class: docker_firewall::nat
#
#
# === Parameters
#
# [*prerouting_purge_ignore*]
#   A list of regexes to use when purging the PREROUTING chain in the nat table.
#   Rules that match one or more of the regexes will not be deleted.
#
# [*prerouting_policy*]
#   The default policy for the PREROUTING chain in the nat table.
#
# [*output_purge_ignore*]
#   A list of regexes to use when purging the OUTPUT chain in the nat table.
#   Rules that match one or more of the regexes will not be deleted.
#
# [*output_policy*]
#   The default policy for the OUTPUT chain in the nat table.
#
# [*postrouting_purge_ignore*]
#   A list of regexes to use when purging the POSTROUTING chain in the nat
#   table. Rules that match one or more of the regexes will not be deleted.
#
# [*postrouting_policy*]
#   The default policy for the POSTROUTING chain in the nat table.
class docker_firewall::nat (
  Variant[String, Array[String]] $prerouting_purge_ignore  = $docker_firewall::prerouting_nat_purge_ignore,
  Optional[String]               $prerouting_policy        = $docker_firewall::prerouting_nat_policy,
  Variant[String, Array[String]] $output_purge_ignore      = $docker_firewall::output_nat_purge_ignore,
  Optional[String]               $output_policy            = $docker_firewall::output_nat_policy,
  Variant[String, Array[String]] $postrouting_purge_ignore = $docker_firewall::postrouting_nat_purge_ignore,
  Optional[String]               $postrouting_policy       = $docker_firewall::postrouting_nat_policy,
) {
  assert_private()

  # PREROUTING
  firewallchain { 'PREROUTING:nat:IPv4':
    ensure => present,
    purge  => true,
    ignore => $prerouting_purge_ignore,
    policy => $prerouting_policy,
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
    ignore => $output_purge_ignore,
    policy => $output_policy,
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
  $default_postrouting_purge_ignore = [
    '^-A POSTROUTING -s (?<source>(?:[0-9]{1,3}\.){3}[0-9]{1,3})\/32 -d (\g<source>)\/32 .* -j MASQUERADE$',
  ]
  $_postrouting_purge_ignore = $postrouting_purge_ignore ? {
    String => [$postrouting_purge_ignore],
    Array  => $postrouting_purge_ignore,
  }
  $final_postrouting_purge_ignore = concat($default_postrouting_purge_ignore, $_postrouting_purge_ignore)
  firewallchain { 'POSTROUTING:nat:IPv4':
    ensure => present,
    purge  => true,
    ignore => $final_postrouting_purge_ignore,
    policy => $postrouting_policy,
  }

  # DOCKER - let Docker manage this chain completely
  firewallchain { 'DOCKER:nat:IPv4':
    ensure => present,
  }
}
