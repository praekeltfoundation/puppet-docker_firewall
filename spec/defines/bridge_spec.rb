require 'spec_helper'

describe 'docker_firewall::bridge' do
  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let(:title) { 'mybridge' }
      let(:facts) do
        add_docker_iface facts, 'mybridge', :network => '172.18.0.0'
      end

      describe 'with docker_firewall defaults' do
        let(:pre_condition) { 'include docker_firewall' }

        it do
          is_expected.not_to contain_firewall(
            '100 DOCKER chain, MASQUERADE mybridge bridge traffic not bound '\
            'to mybridge bridge'
          )
        end

        it do
          is_expected.not_to contain_firewall(
            '200 accept related, established traffic destined for docker0'
          )
        end

        it do
          is_expected.not_to contain_firewall(
            '201 forward traffic destined for docker0 to the DOCKER chain'
          )
        end

        it do
          is_expected.not_to contain_firewall(
            '202 accept traffic originating from docker0 not destined for '\
            'docker0'
          )
        end

        it do
          is_expected.not_to contain_firewall(
            '203 accept traffic originating from docker0 destined for docker0'
          )
        end
      end

      describe 'when facts are not available for the interface' do
        let(:facts) { facts }
        it do
          is_expected.not_to contain_firewall(
            '100 DOCKER chain, MASQUERADE mybridge bridge traffic not bound '\
            'to mybridge bridge'
          )
        end
        it do
          is_expected.not_to contain_firewall(
            '101 accept mybridge traffic to other interfaces on FORWARD chain'
          )
        end
        it do
          is_expected.not_to contain_firewall(
            '102 send FORWARD traffic for mybridge to DOCKER_INPUT chain'
          )
        end
        it do
          is_expected.not_to contain_firewall(
            '100 accept traffic from mybridge DOCKER_INPUT chain'
          )
        end
      end

      describe 'docker_firewall with manage_nat_table set true' do
        let(:pre_condition) do
          <<-EOS
          class { 'docker_firewall':
            manage_nat_table => true,
          }
          EOS
        end

        it do
          is_expected.to contain_firewall(
            '100 DOCKER chain, MASQUERADE mybridge bridge traffic not bound '\
            'to mybridge bridge'
          ).with_table('nat')
            .with_chain('POSTROUTING')
            .with_source('172.18.0.0/16')
            .with_outiface('! mybridge')
            .with_proto('all')
            .with_jump('MASQUERADE')
        end
      end

      describe 'docker_firewall with manage_filter_table set true' do
        let(:pre_condition) do
          <<-EOS
          class { 'docker_firewall':
            manage_filter_table => true,
          }
          EOS
        end

        it do
          is_expected.not_to contain_firewall(
            '100 DOCKER chain, MASQUERADE mybridge bridge traffic not bound '\
            'to mybridge bridge'
          )
        end

        it do
          is_expected.to contain_firewall(
            '200 accept related, established traffic destined for mybridge'
          ).with_table('filter')
            .with_chain('FORWARD')
            .with_outiface('mybridge')
            .with_ctstate(['RELATED', 'ESTABLISHED'])
            .with_proto('all')
            .with_action('accept')
        end

        it do
          is_expected.to contain_firewall(
            '201 forward traffic destined for mybridge to the DOCKER chain'
          ).with_table('filter')
            .with_chain('FORWARD')
            .with_outiface('mybridge')
            .with_proto('all')
            .with_jump('DOCKER')
        end

        it do
          is_expected.to contain_firewall(
            '202 accept traffic originating from mybridge not destined for '\
            'mybridge'
          ).with_table('filter')
            .with_chain('FORWARD')
            .with_iniface('mybridge')
            .with_outiface('! mybridge')
            .with_proto('all')
            .with_action('accept')
        end

        it do
          is_expected.to contain_firewall(
            '203 accept traffic originating from mybridge destined for '\
            'mybridge'
          ).with_table('filter')
            .with_chain('FORWARD')
            .with_iniface('mybridge')
            .with_outiface('mybridge')
            .with_proto('all')
            .with_action('accept')
        end
      end
    end
  end
end
