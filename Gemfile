source 'https://rubygems.org'

group :test do
  gem 'rake'

  gem 'puppet', ENV['PUPPET_VERSION'] || '>= 3.4.0'

  gem 'librarian-puppet'
  gem 'metadata-json-lint'
  gem 'puppetlabs_spec_helper'
  gem 'rspec-puppet-facts'

  gem 'rubocop', RUBY_VERSION < '2.0' ? '~> 0.41.2' : '~> 0.47.1'
end
