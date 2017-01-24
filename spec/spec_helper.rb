require 'puppetlabs_spec_helper/module_spec_helper'

require 'rspec-puppet-facts'
include RspecPuppetFacts

# Add facts for the docker0 interface
def add_docker0(facts)
  interfaces_arr = facts[:interfaces].split(',')
  interfaces_arr << 'docker0'
  interfaces = interfaces_arr.sort.uniq.join(',')

  facts.merge(
    :interfaces => interfaces,
    :ipaddress_docker0 => '172.17.0.1',
    :macaddress_docker0 => '02:42:41:0b:31:b8',
    :mtu_docker0 => '1500',
    :netmask_docker0 => '255.255.0.0',
    :network_docker0 => '172.17.0.0'
  )
end
