# == Define: docker_firewall::bridge
#
# Set up firewall rules specifically for a certain bridge interface. The bridge
# interface name should be the title (or name) of the resource.
define docker_firewall::bridge () {
  if has_interface_with($name) {
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

    # -A FORWARD -i docker0 ! -o docker0 -j ACCEPT
    firewall { "101 accept ${name} traffic to other interfaces on FORWARD chain":
      table    => 'filter',
      chain    => 'FORWARD',
      iniface  => $name,
      outiface => "! ${name}",
      proto    => 'all',
      action   => 'accept',
    }

    # -A FORWARD -o docker0 -j DOCKER_INPUT
    firewall { "102 send FORWARD traffic for ${name} to DOCKER_INPUT chain":
      table    => 'filter',
      chain    => 'FORWARD',
      outiface => $name,
      proto    => 'all',
      jump     => 'DOCKER_INPUT',
    }

    # -A DOCKER_INPUT -i docker0 -j ACCEPT
    firewall { "100 accept traffic from ${name} DOCKER_INPUT chain":
      table   => 'filter',
      chain   => 'DOCKER_INPUT',
      iniface => $name,
      proto   => 'all',
      action  => 'accept',
    }
  } else {
    warning("The ${name} interface has not been detected by Facter yet. You \
      may need to re-run Puppet and/or ensure that the Docker service is \
      started.")
  }
}
