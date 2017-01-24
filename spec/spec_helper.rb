require 'puppetlabs_spec_helper/module_spec_helper'

require 'rspec-puppet-facts'
include RspecPuppetFacts

# Add facts for a Docker bridge interface
def add_docker_iface(facts, name = 'docker0', params = {})
  interface_params = {
    :ipaddress => '172.17.0.1',
    :macaddress => '02:42:41:0b:31:b8',
    :mtu => '1500',
    :netmask => '255.255.0.0',
    :network => '172.17.0.0'
  }.merge(params)
  new_facts = Hash[interface_params.map { |k, v| ["#{k}_#{name}".to_sym, v] }]

  interfaces = facts[:interfaces].split(',')
  interfaces << name
  new_facts[:interfaces] = interfaces.sort.uniq.join(',')

  facts.merge(new_facts)
end
