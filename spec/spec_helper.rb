require 'puppetlabs_spec_helper/module_spec_helper'

require 'rspec-puppet-facts'
include RspecPuppetFacts

# Add facts for the docker0 interface
def add_interface(new_interface, existing_interfaces)
  interfaces = existing_interfaces.split(',')
  interfaces << new_interface
  interfaces.sort.uniq.join(',')
end

add_custom_fact(
  :interfaces,
  ->(_os, facts) { add_interface('docker0', facts[:interfaces]) }
)
{
  :ipaddress_docker0 => '172.17.0.1',
  :macaddress_docker0 => '02:42:41:0b:31:b8',
  :mtu_docker0 => '1500',
  :netmask_docker0 => '255.255.0.0',
  :network_docker0 => '172.17.0.0'
}.each { |k, v| add_custom_fact k, v }
