# puppet-docker_firewall
Puppet module for simplifying the management of iptables rules when running Docker

Docker makes extensive use of iptables to enable features like port-forwarding and inter-container communication when using bridge-mode networking. Unfortunately, the way Docker configures iptables makes it difficult to limit access to containers from the outside world.

The `docker_firewall` class aims to make running custom iptables rules alongside Docker easier. It manages the static iptables rules that Docker creates when its daemon starts and allows Docker to dynamically create rules as containers are started.

For example:
```puppet
class { 'docker_firewall':
  accept_eth1 => true,
  subscribe   => Service['docker'],
}
```
This sets up the Docker iptables rules and allows access to containers from connections incoming from the `eth1` interface, while dropping external connections from other interfaces.

There are a few important things to note here:
* This class will purge several iptables chains. Your unmanaged rules in those chains will be deleted.
* The class must be executed every time the Docker daemon starts, as each time Docker will re-add its own rules. Unfortunately, this means that there is a small amount of time between Docker starting up and the `docker_firewall` class being applied when containers may be exposed to outside connections.
* Using this class at the same time as you install Docker may require a second run of Puppet as Facter will need a chance to pick up details about Docker's bridge interface (`docker0`).

For more information, see the [manifest source](manifests/init.pp).
