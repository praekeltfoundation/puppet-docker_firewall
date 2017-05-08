# == Class: docker_firewall::filter
#
# === Parameters
#
# [*forward_filter_purge_ignore*]
#   A list of regexes to use when purging the OUTPUT chain in the nat table.
#   Rules that match one or more of the regexes will not be deleted.
#
# [*forward_policy*]
#   The default policy for the FORWARD chain in the filter table. The default is
#   'drop'.
class docker_firewall::filter (
  Variant[String, Array[String]] $forward_purge_ignore  = $docker_firewall::forward_filter_purge_ignore,
  Optional[String]               $forward_policy        = $docker_firewall::forward_filter_policy,
) {
  assert_private()

  # FORWARD
  firewallchain { 'FORWARD:filter:IPv4':
    purge  => true,
    ignore => $forward_purge_ignore,
    policy => $forward_policy,
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
}
