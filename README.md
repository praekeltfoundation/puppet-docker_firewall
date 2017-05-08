# puppet-docker_firewall
Puppet module for simplifying the management of iptables rules when running Docker

Docker makes extensive use of iptables to enable features like port-forwarding and inter-container communication when using bridge-mode networking. Unfortunately, the way Docker configures iptables makes it difficult to limit access to containers from the outside world.

The `docker_firewall` class aims to make running custom iptables rules alongside Docker easier. It manages the static iptables rules that Docker creates when its daemon starts and allows Docker to dynamically create rules as containers are started.

***Please read all of this document if it is important to you that your containers cannot be accessed from the outside world.***

## Usage
```puppet
class { 'docker_firewall':
  accept_rules => {
    '200 accept eth1 traffic' => {
      'iniface' => 'eth1',
      'proto'   => 'all',
    },
  },
  subscribe    => Service['docker'],
}
```
This sets up the Docker iptables rules and allows access to containers from connections incoming from the `eth1` interface, while dropping external connections from other interfaces.

## Managed chains
The module can manage all the iptables chains that Docker touches, depending on how it is configured. With more recent versions of Docker, fewer iptables rules and chains need to be managed. With older versions of Docker, this module can be used to adjust the iptables rules to match those produced by newer versions of Docker.

The two parameters that control which chains are managed are the `$manage_nat_table` and `$manage_filter_table` parameters. When these are set `true`, the following chains will be managed:
**nat table**
* `PREROUTING`
* `OUTPUT`
* `POSTROUTING`

**filter table**
* `FORWARD`

By default, these parameters are `false`. Set `true`, the chains will be purged and unmanaged rules will be removed. You can adjust which rules are *not* removed using the `<chain>_purge_ignore` parameters. See the [`docker_firewall::nat`](manifests/nat.pp) and [`docker_firewall::filter`](manifests/filter.pp) classes for more information.

By default, the policies of the chains will not be managed. You can use the `<chain>_policy` parameters to adjust this. The exception to this is the `filter`/`FORWARD` chain which, by default, will be set to have a policy of `DROP`. This is something the Docker daemon does since version 1.13.0. For more information see [this discussion](https://github.com/docker/docker/issues/14041).

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

The `$accept_rules` parameter for the main `docker_firewall` class provides an easy way to set up rules to accept connections to Docker containers. This parameter takes a hash of `firewall` resources to create, and defaults those rules to be in the `DOCKER_INPUT` chain and jump to the `DOCKER` chain. This parameter is probably best set using Hiera, for example:
```yaml
docker_firewall::accept_rules:
  200 accept all traffic from 192.168.0.1/32:
    source: 192.168.0.1/32
    proto: all
```

## Docker daemon restarts
This class should be used in combination with the `--iptables=true` flag (the default) when starting the Docker daemon. We *want* Docker to manage iptables rules for each container.

The Docker daemon normally won't rewrite or change rules in iptables if it sees that its rules are already present. Even though we copy most of Docker's rules, because the `puppetlabs/firewall` module adds comments to each rule it creates, Docker thinks that its rules aren't present. So it goes ahead and re-adds all its rules, generally inserting them before the Puppet-created rules.

This means that when the Docker daemon restarts there may be some time before the `docker_firewall` class is applied that the **containers on the machine may be exposed to outside connections**.

You should ensure that the `docker_firewall` class always runs after the Docker service restarts.

## Facter and the `docker0` interface
Using this module at the same time as you install Docker may require a second run of Puppet as Facter will need a chance to pick up details about Docker's bridge interface (`docker0`). In order to set up the firewall, the `$::network_docker0` fact must be set.

## Custom bridge interfaces
When setting up a custom Docker bridge network (available since Docker 1.9.0), extra iptables rules are needed for each network. It's possible to define extra bridge interfaces using the `$bridges` parameter for the `docker_firewall` class or by defining `docker_firewall::bridge` resources.

**NOTE:** You must specify the _actual_ bridge interface name when creating the network, for example:
```
docker network create -d bridge -o com.docker.network.bridge.name=br-mynetwork mynetwork
```
In this example we are interested in the name `br-mynetwork` which is the name of the interface that Docker creates for the network. This is the name that should be used for the `docker_firewall::bridge` resource.

If the `com.docker.network.bridge.name` option is not specified when the network is created, Docker will generate an interface name consisting of the hash identifier for the network, for example `br-d108dbddb4c8`.

This system currently doesn't support any non-default options such as internal mode (`--internal`) or hairpin-mode routing (`--userland-proxy=false`).

Ideally, some Puppet module would export facts about the Docker interface names and we could pick them up and configure the firewall rules with less input from the user.

## Credits
The `DOCKER_INPUT` chain was inspired by the idea of a `PRE_DOCKER` chain as described in [this blog post](http://rudijs.github.io/2015-07/docker-restricting-container-access-with-iptables/) by Rudi Starcevic.

Many of the Puppet firewall rules were adapted from the [`hesco-weave`](https://github.com/hesco/hesco-weave) Puppet module source.
