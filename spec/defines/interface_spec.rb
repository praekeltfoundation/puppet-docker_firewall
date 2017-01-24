require 'spec_helper'

describe 'docker_firewall::interface' do
  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let(:title) { 'docker0' }

      describe 'when facts are available for the interface' do
        let(:facts) { add_docker_iface facts }

        it do
          is_expected.to contain_firewall(
            '100 DOCKER chain, MASQUERADE docker0 bridge traffic not bound to '\
            'docker0 bridge'
          ).with_table('nat')
            .with_chain('POSTROUTING')
            .with_source('172.17.0.0/16')
            .with_outiface('! docker0')
            .with_proto('all')
            .with_jump('MASQUERADE')
        end

        it do
          is_expected.to contain_firewall(
            '101 accept docker0 traffic to other interfaces on FORWARD chain'
          ).with_table('filter')
            .with_chain('FORWARD')
            .with_iniface('docker0')
            .with_outiface('! docker0')
            .with_proto('all')
            .with_action('accept')
        end

        it do
          is_expected.to contain_firewall(
            '102 send FORWARD traffic for docker0 to DOCKER_INPUT chain'
          ).with_table('filter')
            .with_chain('FORWARD')
            .with_outiface('docker0')
            .with_proto('all')
            .with_jump('DOCKER_INPUT')
        end

        it do
          is_expected.to contain_firewall(
            '100 accept traffic from docker0 DOCKER_INPUT chain'
          ).with_table('filter')
            .with_chain('DOCKER_INPUT')
            .with_iniface('docker0')
            .with_proto('all')
            .with_action('accept')
        end
      end

      describe 'when facts are not available for the interface' do
        let(:facts) { facts }
        it do
          is_expected.not_to contain_firewall(
            '100 DOCKER chain, MASQUERADE docker0 bridge traffic not bound to '\
            'docker0 bridge'
          )
        end
        it do
          is_expected.not_to contain_firewall(
            '101 accept docker0 traffic to other interfaces on FORWARD chain'
          )
        end
        it do
          is_expected.not_to contain_firewall(
            '102 send FORWARD traffic for docker0 to DOCKER_INPUT chain'
          )
        end
        it do
          is_expected.not_to contain_firewall(
            '100 accept traffic from docker0 DOCKER_INPUT chain'
          )
        end
      end

      describe 'with a custom bridge interface' do
        let(:title) { 'br-d108dbddb4c8' }
        let(:facts) do
          add_docker_iface facts, 'br-d108dbddb4c8', :network => '172.18.0.0'
        end

        it do
          is_expected.to contain_docker_firewall__interface('br-d108dbddb4c8')
        end

        it do
          is_expected.to contain_firewall(
            '100 DOCKER chain, MASQUERADE br-d108dbddb4c8 bridge traffic not '\
            'bound to br-d108dbddb4c8 bridge'
          ).with_table('nat')
            .with_chain('POSTROUTING')
            .with_source('172.18.0.0/16')
            .with_outiface('! br-d108dbddb4c8')
            .with_proto('all')
            .with_jump('MASQUERADE')
        end

        it do
          is_expected.to contain_firewall(
            '101 accept br-d108dbddb4c8 traffic to other interfaces on '\
            'FORWARD chain'
          ).with_table('filter')
            .with_chain('FORWARD')
            .with_iniface('br-d108dbddb4c8')
            .with_outiface('! br-d108dbddb4c8')
            .with_proto('all')
            .with_action('accept')
        end

        it do
          is_expected.to contain_firewall(
            '102 send FORWARD traffic for br-d108dbddb4c8 to DOCKER_INPUT chain'
          ).with_table('filter')
            .with_chain('FORWARD')
            .with_outiface('br-d108dbddb4c8')
            .with_proto('all')
            .with_jump('DOCKER_INPUT')
        end

        it do
          is_expected.to contain_firewall(
            '100 accept traffic from br-d108dbddb4c8 DOCKER_INPUT chain'
          ).with_table('filter')
            .with_chain('DOCKER_INPUT')
            .with_iniface('br-d108dbddb4c8')
            .with_proto('all')
            .with_action('accept')
        end
      end
    end
  end
end
