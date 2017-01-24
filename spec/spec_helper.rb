require 'puppetlabs_spec_helper/module_spec_helper'

require 'rspec-puppet-facts'
include RspecPuppetFacts

# Add facts for a Docker bridge interface
def add_docker_iface(facts, name = 'docker0', params = {})
  interfaces = facts[:interfaces].split(',')
  interfaces << name
  facts[:interfaces] = interfaces.sort.uniq.join(',')

  interface_params = {
    :ipaddress => '172.17.0.1',
    :macaddress => '02:42:41:0b:31:b8',
    :mtu => '1500',
    :netmask => '255.255.0.0',
    :network => '172.17.0.0'
  }.merge(params)
  facts.merge(
    Hash[interface_params.map { |k, v| ["#{k}_#{name}".to_sym, v] }]
  )
end
