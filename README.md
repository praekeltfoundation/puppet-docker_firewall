# puppet-docker_firewall
Puppet module for simplifying the management of iptables rules when running Docker

Docker makes extensive use of iptables to enable features like port-forwarding and inter-container communication when using bridge-mode networking. Unfortunately, the way Docker configures iptables makes it difficult to limit access to containers from the outside world.

The `docker_firewall` class aims to make running custom iptables rules alongside Docker easier. It manages the static iptables rules that Docker creates when its daemon starts and allows Docker to dynamically create rules as containers are started.

***Please read all of this document if it is important to you that your containers cannot be accessed from the outside world.***

## Usage
```puppet
class { 'docker_firewall':
  accept_eth1 => true,
  subscribe   => Service['docker'],
}
```
This sets up the Docker iptables rules and allows access to containers from connections incoming from the `eth1` interface, while dropping external connections from other interfaces.

## Managed chains
The module manages all the iptables chains that Docker touches. The chains will be purged and unmanaged rules will be removed. You can adjust this behaviour using the `<chain>_purge_ignore` and `<chain>_policy` parameters. See the [manifest source](manifests/init.pp) for more information.

The following chains will be purged:  
**nat table**
* `PREROUTING`
* `OUTPUT`
* `POSTROUTING`

**filter table**
* `FORWARD`

In addition, the `DOCKER` chain in the nat table and the `DOCKER` and `DOCKER-ISOLATION` chains in the filter table are managed but not purged. Rules in these chains are created by the Docker daemon and should not be changed.

## `DOCKER_INPUT` chain
The major functionality of the class (limiting outside connections to containers) works by adding a chain called `DOCKER_INPUT` that handles connections destined for the `docker0` interface. This chain can be used much like the `INPUT` chain in the filter table would typically be used to whitelist connections, but instead of `ACCEPT`-ing connections, rather jump to the `DOCKER` chain.

For example, for a regular input rule that allows connections from
`192.168.0.1` you could do something like:
```
-A INPUT -s 192.168.0.1/32 -j ACCEPT
```
To allow access to Docker containers you would do:
```
-A DOCKER_INPUT -s 192.168.0.1/32 -j DOCKER
```

## Docker daemon restarts
This class should be used in combination with the `--iptables=true` flag (the default) when starting the Docker daemon. We *want* Docker to manage iptables rules for each container.

The Docker daemon normally won't rewrite or change rules in iptables if it sees that its rules are already present. Even though we copy most of Docker's rules, because the `puppetlabs/firewall` module adds comments to each rule it creates, Docker thinks that its rules aren't present. So it goes ahead and re-adds all its rules, generally inserting them before the Puppet-created rules.

This means that when the Docker daemon restarts there may be some time before the `docker_firewall` class is applied that the **containers on the machine may be exposed to outside connections**.

You should ensure that the `docker_firewall` class always runs after the Docker service restarts.

## Facter and the `docker0` interface
Using this module at the same time as you install Docker may require a second run of Puppet as Facter will need a chance to pick up details about Docker's bridge interface (`docker0`). In order to set up the firewall, the `$::network_docker0` fact must be set.

## Credits
The `DOCKER_INPUT` chain was inspired by the idea of a `PRE_DOCKER` chain as described in [this blog post](http://rudijs.github.io/2015-07/docker-restricting-container-access-with-iptables/) by Rudi Starcevic.

Many of the Puppet firewall rules were adapted from the [`hesco-weave`](https://github.com/hesco/hesco-weave) Puppet module source.
