require 'spec_helper'

describe 'docker_firewall' do
  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let(:facts) { add_docker0(facts) }

      it { should compile }

      describe 'with default options' do
        it { is_expected.to contain_class('firewall') }

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
          is_expected.to contain_firewall(
            '100 DOCKER chain, MASQUERADE docker bridge traffic not bound to '\
            'docker bridge'
          ).with_table('nat')
            .with_chain('POSTROUTING')
            .with_source('172.17.0.0/16')
            .with_outiface('! docker0')
            .with_proto('all')
            .with_jump('MASQUERADE')
        end

        it do
          is_expected.to contain_firewallchain('DOCKER:nat:IPv4')
            .with_ensure('present')
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
          ).with_table('filter')
            .with_chain('FORWARD')
            .with_iniface('docker0')
            .with_outiface('! docker0')
            .with_proto('all')
            .with_action('accept')
        end

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
          is_expected.to contain_firewall(
            '102 send FORWARD traffic for docker0 to DOCKER_INPUT chain'
          ).with_table('filter')
            .with_chain('FORWARD')
            .with_outiface('docker0')
            .with_proto('all')
            .with_jump('DOCKER_INPUT')
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

      describe "when facts aren't available for docker0" do
        let(:facts) { facts }

        it do
          is_expected.not_to contain_firewall(
            '100 DOCKER chain, MASQUERADE docker bridge traffic not bound to '\
            'docker bridge'
          )
        end
      end
    end
  end
end
