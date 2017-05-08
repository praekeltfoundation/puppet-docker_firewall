require 'spec_helper'

describe 'docker_firewall' do
  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let(:facts) { add_docker_iface facts }

      it { is_expected.to compile }

      describe 'with default options' do
        it { is_expected.to contain_class('docker_firewall') }

        it { is_expected.to contain_class('firewall') }

        it do
          is_expected.to contain_firewallchain('DOCKER:filter:IPv4')
            .with_ensure('present')
        end

        it do
          is_expected.to contain_firewallchain('DOCKER_INPUT:filter:IPv4')
            .with_ensure('present')
            .with_purge(true)
        end

        it do
          is_expected.to contain_firewall('999 drop DOCKER_INPUT traffic')
            .with_table('filter')
            .with_chain('DOCKER_INPUT')
            .with_proto('all')
            .with_action('drop')
        end

        it do
          is_expected.to contain_firewall(
            '100 accept related, established traffic in DOCKER_INPUT chain'
          ).with_table('filter')
            .with_chain('DOCKER_INPUT')
            .with_ctstate(['RELATED', 'ESTABLISHED'])
            .with_proto('all')
            .with_action('accept')
        end

        # Default docker0 bridge and associated rules
        it { is_expected.to contain_docker_firewall__bridge('docker0') }

        it do
          is_expected.to contain_firewall(
            '102 send FORWARD traffic for docker0 to DOCKER_INPUT chain'
          )
        end

        it do
          is_expected.to contain_firewall(
            '100 accept traffic from docker0 DOCKER_INPUT chain'
          )
        end
      end

      describe 'with manage_nat_table set true' do
        let(:params) { {:manage_nat_table => true} }

        it do
          is_expected.to contain_class('docker_firewall::nat').with(
            :prerouting_purge_ignore => [],
            :prerouting_policy => nil,
            :output_purge_ignore => [],
            :output_policy => nil,
            :postrouting_purge_ignore => [],
            :postrouting_policy => nil
          )
        end

        it do
          is_expected.to contain_firewallchain('PREROUTING:nat:IPv4')
            .with_ensure('present')
            .with_purge(true)
            .with_ignore([])
            .with_policy(nil)
        end

        it do
          is_expected.to contain_firewall(
            '100 DOCKER table PREROUTING LOCAL traffic'
          ).with_table('nat')
            .with_chain('PREROUTING')
            .with_dst_type('LOCAL')
            .with_proto('all')
            .with_jump('DOCKER')
        end

        it do
          is_expected.to contain_firewallchain('OUTPUT:nat:IPv4')
            .with_ensure('present')
            .with_purge(true)
            .with_ignore([])
            .with_policy(nil)
        end

        it do
          is_expected.to contain_firewall(
            '100 DOCKER chain, route LOCAL non-loopback traffic to DOCKER'
          ).with_table('nat')
            .with_chain('OUTPUT')
            .with_destination('! 127.0.0.0/8')
            .with_dst_type('LOCAL')
            .with_proto('all')
            .with_jump('DOCKER')
        end

        it do
          is_expected.to contain_firewallchain('POSTROUTING:nat:IPv4')
            .with_ensure('present')
            .with_purge(true)
            .with_ignore(
              [
                '^-A POSTROUTING -s (?<source>(?:[0-9]{1,3}\.){3}[0-9]{1,3})\/'\
                '32 -d (\g<source>)\/32 .* -j MASQUERADE$'
              ]
            ).with_policy(nil)
        end

        it do
          is_expected.to contain_firewallchain('DOCKER:nat:IPv4')
            .with_ensure('present')
        end

        it do
          is_expected.to contain_firewall(
            '100 DOCKER chain, MASQUERADE docker0 bridge traffic not bound to '\
            'docker0 bridge'
          )
        end
      end

      describe 'with manage_filter_table set true' do
        let(:params) { {:manage_filter_table => true} }

        it do
          is_expected.to contain_class('docker_firewall::filter').with(
            :forward_purge_ignore => [],
            :forward_policy => 'drop'
          )
        end

        it do
          is_expected.to contain_firewallchain('FORWARD:filter:IPv4')
            .with_purge(true)
            .with_ignore([])
            .with_policy('drop')
        end

        it do
          is_expected.to contain_firewallchain('DOCKER-ISOLATION:filter:IPv4')
            .with_ensure('present')
        end

        it do
          is_expected.to contain_firewall(
            '100 send FORWARD traffic to DOCKER-ISOLATION chain'
          ).with_table('filter')
            .with_chain('FORWARD')
            .with_proto('all')
            .with_jump('DOCKER-ISOLATION')
        end

        it do
          is_expected.to contain_firewall(
            '101 accept docker0 traffic to other interfaces on FORWARD chain'
          )
        end
      end

      describe 'with custom purge and policy parameters' do
        let(:params) do
          {
            :manage_nat_table => true,
            :prerouting_nat_purge_ignore => ['foobar'],
            :prerouting_nat_policy => 'drop',
            :output_nat_purge_ignore => ['foobaz'],
            :output_nat_policy => 'reject',
            :postrouting_nat_purge_ignore => ['barbaz'],
            :postrouting_nat_policy => 'drop',
            :manage_filter_table => true,
            :forward_filter_purge_ignore => ['barfoo'],
            :forward_filter_policy => 'accept'
          }
        end

        it do
          is_expected.to contain_firewallchain('PREROUTING:nat:IPv4')
            .with_ignore(['foobar'])
            .with_policy('drop')
        end

        it do
          is_expected.to contain_firewallchain('OUTPUT:nat:IPv4')
            .with_ignore(['foobaz'])
            .with_policy('reject')
        end

        it do
          is_expected.to contain_firewallchain('POSTROUTING:nat:IPv4')
            .with_ignore(
              [
                '^-A POSTROUTING -s (?<source>(?:[0-9]{1,3}\.){3}[0-9]{1,3})\/'\
                '32 -d (\g<source>)\/32 .* -j MASQUERADE$',
                'barbaz'
              ]
            ).with_policy('drop')
        end

        it do
          is_expected.to contain_firewallchain('FORWARD:filter:IPv4')
            .with_ignore(['barfoo'])
            .with_policy('accept')
        end
      end

      describe 'with custom string ignore policies' do
        let(:params) do
          {
            :manage_nat_table => true,
            :prerouting_nat_purge_ignore => 'foobar',
            :output_nat_purge_ignore => 'foobaz',
            :postrouting_nat_purge_ignore => 'barbaz',
            :manage_filter_table => true,
            :forward_filter_purge_ignore => 'barfoo',
          }
        end

        it do
          is_expected.to contain_firewallchain('PREROUTING:nat:IPv4')
            .with_ignore('foobar')
        end

        it do
          is_expected.to contain_firewallchain('OUTPUT:nat:IPv4')
            .with_ignore('foobaz')
        end

        it do
          is_expected.to contain_firewallchain('POSTROUTING:nat:IPv4')
            .with_ignore(
              [
                '^-A POSTROUTING -s (?<source>(?:[0-9]{1,3}\.){3}[0-9]{1,3})\/'\
                '32 -d (\g<source>)\/32 .* -j MASQUERADE$',
                'barbaz'
              ]
            )
        end

        it do
          is_expected.to contain_firewallchain('FORWARD:filter:IPv4')
            .with_ignore('barfoo')
        end
      end

      describe 'when a custom accept rule is provided' do
        let(:params) do
          {
            :accept_rules => {
              '200 accept port 5000 tcp traffic' => {
                'dport' => 5000,
                'proto' => 'tcp',
              }
            }
          }
        end

        it do
          is_expected.to contain_firewall('200 accept port 5000 tcp traffic')
            .with_dport(5000)
            .with_proto('tcp')
            .with_table('filter')
            .with_chain('DOCKER_INPUT')
            .with_jump('DOCKER')
        end
      end

      describe 'with an extra bridge interface' do
        let(:params) { {:bridges => {'br-d108dbddb4c8' => {}}} }

        it do
          is_expected.to contain_docker_firewall__bridge('br-d108dbddb4c8')
        end
        it { is_expected.to contain_docker_firewall__bridge('docker0') }
      end
    end
  end
end
