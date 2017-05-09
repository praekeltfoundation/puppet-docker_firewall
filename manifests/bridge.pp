# == Define: docker_firewall::bridge
#
# Set up firewall rules specifically for a certain bridge interface. The bridge
# interface name should be the title (or name) of the resource.
define docker_firewall::bridge () {
  if has_interface_with($name) {
    if $docker_firewall::manage_nat_table {
      # -A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
      $source = getvar("::network_${name}")
      firewall { "100 DOCKER chain, MASQUERADE ${name} bridge traffic not bound to ${name} bridge":
        table    => 'nat',
        chain    => 'POSTROUTING',
        source   => "${source}/16",
        outiface => "! ${name}",
        proto    => 'all',
        jump     => 'MASQUERADE',
      }

      # TODO: additional MASQUERADE rule if --userland-proxy=false
    }

    if $docker_firewall::manage_filter_table {
      # These are the static firewall rules that the Docker daemon sets up for
      # bridge networks with default settings as of Docker 17.05.0.
      firewall {
        default:
          table => 'filter',
          chain => 'FORWARD';

        # -A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        # Changed order in Docker 17.04.0:
        # https://github.com/docker/libnetwork/pull/961
        "200 accept related, established traffic destined for ${name}":
          outiface => $name,
          ctstate  => ['RELATED', 'ESTABLISHED'],
          proto    => 'all',
          action   => 'accept';

        # -A FORWARD -o docker0 -j DOCKER
        "201 forward traffic destined for ${name} to the DOCKER chain":
          outiface => $name,
          proto    => 'all',
          jump     => 'DOCKER';

        # -A FORWARD -i docker0 ! -o docker0 -j ACCEPT
        "202 accept traffic originating from ${name} not destined for ${name}":
          iniface  => $name,
          outiface => "! ${name}",
          proto    => 'all',
          action   => 'accept';

        # -A FORWARD -i docker0 -o docker0 -j ACCEPT
        "203 accept traffic originating from ${name} destined for ${name}":
          iniface  => $name,
          outiface => $name,
          proto    => 'all',
          action   => 'accept';
      }
    }
  } else {
    warning("The ${name} interface has not been detected by Facter yet. You \
      may need to re-run Puppet and/or ensure that the Docker service is \
      started.")
  }
}
