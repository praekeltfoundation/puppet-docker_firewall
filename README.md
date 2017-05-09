# puppet-docker_firewall

> NOTE: There have been some significant changes to how this module works between each major point release. We've changed our minds a lot (and so has Docker). We recommend that you pin the version of this module you use and read this README thoroughly before upgrading.

Puppet module for simplifying the management of iptables rules when running Docker

Docker makes extensive use of iptables to enable features like port-forwarding and inter-container communication when using bridge-mode networking. Unfortunately, the way Docker configures iptables makes it difficult to limit access to containers from the outside world.

The `docker_firewall` class aims to make running custom iptables rules alongside Docker easier. It (optionally) manages the static iptables rules that Docker creates when its daemon starts and allows Docker to dynamically create rules as containers are started.

***Please read all of this document if it is important to you that your containers cannot be accessed from the outside world.***

## Usage
```puppet
class { 'docker_firewall':
  drop_rules => {
    '200 drop eth0 traffic' => {
      'iniface' => 'eth0',
      'proto'   => 'all',
    },
  },
  subscribe  => Service['docker'],
}
```
This sets up the Docker iptables rules and blocks access to containers from connections incoming from the `eth0` interface, while allowing external connections from other interfaces.

## Managed chains
The module can manage all the iptables chains that Docker touches, depending on how it is configured. With more recent versions of Docker, fewer iptables rules and chains need to be managed. With older versions of Docker, this module can be used to adjust the iptables rules to match those produced by newer versions of Docker.

The two boolean parameters that control which chains are managed are the `$manage_nat_table` and `$manage_filter_table` parameters. Both default to `false`, but may need to be adjusted depending on the version of Docker you are using:
* `$manage_nat_table` can be set `true` with any version of Docker but should only be used if you want Puppet to manage as many of Docker's iptables rules as possible.
* `$manage_filter_table` **must be set `true` with versions of Docker less than 17.04.0** in order for this firewall setup to work correctly. It can also be set `true` for newer Docker versions if you would like Puppet to manage as many of Docker's iptables rules as possible.

> In general, we would recommend letting the Docker daemon manage as many of its own rules as possible. The dynamic manipulation of iptables rules by the Docker daemon is not really compatible with the model of static rules that the Puppet firewall module was designed around.

When these parameters are set `true`, the following chains will be managed:
##### `$manage_nat_table`: nat table
* `PREROUTING`
* `OUTPUT`
* `POSTROUTING`

##### `$manage_filter_table`: filter table
* `FORWARD`

When these parameters are set `true`, the chains will be purged and unmanaged rules will be removed. You can adjust which rules are *not* removed using the `<chain>_purge_ignore` parameters. See the [`docker_firewall::nat`](manifests/nat.pp) and [`docker_firewall::filter`](manifests/filter.pp) classes for more information.

By default, the policies of the chains will not be managed. You can use the `<chain>_policy` parameters to adjust this. The exception to this is the `filter`/`FORWARD` chain which, by default, will be set to have a policy of `DROP`. This is something the Docker daemon does since version 1.13.0. For more information see [this discussion](https://github.com/docker/docker/issues/14041).

In addition, the `DOCKER` chain in the nat table and the `DOCKER` and `DOCKER-ISOLATION` chains in the filter table are managed but not purged. Rules in these chains are created by the Docker daemon and should not be changed.

## `DOCKER_INPUT` chain
The major functionality of the class (limiting outside connections to containers) works by adding a chain called `DOCKER_INPUT` that handles all connections before they pass through the `DOCKER` chain.

This works by injecting a rule into the front of the `DOCKER` chain that jumps to the `DOCKER_INPUT` chain. This is the only method recommended by Docker for limiting access to containers and is briefly mentioned in the documentation [here](https://docs.docker.com/engine/userguide/networking/default_network/container-communication/#communicating-to-the-outside-world).

The `DOCKER_INPUT` chain works as a blacklist for connections. Users should add rules to the `DOCKER_INPUT` chain that either `DROP` unwanted packets, or `RETURN` acceptable packets to the `DOCKER` chain. For example:
```puppet
firewall { '300 allow eth0 access from trusted address':
  chain   => 'DOCKER_INPUT',
  iniface => 'eth0',
  source  => '216.58.223.3/32',
  action  => 'return',
}

firewall { '999 drop all incoming eth0 connections':
  chain   => 'DOCKER_INPUT',
  iniface => 'eth0',
  proto   => 'all',
  action  => 'drop',
}
```

For convenience, the `docker_firewall` class provides the `$drop_rules` and `$accept_rules` parameters that take hashes of `firewall` resources with the correct `chain` and `action` parameters set to either drop or accept (return) packets. Doing the equivalent of the above Puppet code in Hiera would look like this:
```yaml
docker_firewall::accept_rules:
  300 allow eth0 access from trusted address:
    iniface: eth0
    source: 216.58.223.3/32

docker_firewall::drop_rules:
  999 drop all incoming eth0 connections:
    iniface: eth0
    proto: all
```

**NOTE** that the default is to accept packets (this is a blacklist system). Accept rules without a **corresponding drop rule that appears later in the chain** will have no effect.

## Docker daemon restarts
This class should be used in combination with the `--iptables=true` flag (the default) when starting the Docker daemon. We *want* Docker to manage iptables rules for each container.

The Docker daemon normally won't rewrite or change rules in iptables if it sees that its rules are already present. Even though we copy most of Docker's rules, because the `puppetlabs/firewall` module adds comments to each rule it creates, Docker thinks that its rules aren't present. So it goes ahead and re-adds all its rules, generally inserting them before the Puppet-created rules.

This means that when the Docker daemon restarts there may be some time before the `docker_firewall` class is applied that the **containers on the machine may be exposed to outside connections**.

You should ensure that the `docker_firewall` class always runs after the Docker service restarts.

## Facter and Docker's bridge interfaces
Using this module at the same time as you install Docker may require a second run of Puppet if `$manage_nat_table` is `true`. Facter will need another run to pick up details about Docker's bridge interfaces (e.g. `docker0`) if an interface was created during the current Puppet run. In order to set up the firewall rules for the nat table, the `$::network_<bridge-name>` (e.g. `$::network_docker0`) fact must be set.

## Custom bridge interfaces
> NOTE: Defining `docker_firewall::bridge` resources is only necessary if either of the `$manage_nat_table` or `$manage_filter_table` parameters for the `docker_firewall` class are `true`. When both are `false`, `bridge` resources do nothing.

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
