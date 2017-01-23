require 'puppetlabs_spec_helper/rake_tasks'
require 'metadata-json-lint/rake_task'
require 'rubocop/rake_task'

task :librarian_spec_prep do
  sh 'librarian-puppet install --path=spec/fixtures/modules/'
end
task :spec_prep => :librarian_spec_prep

Rake::Task[:lint].clear
PuppetLint::RakeTask.new(:lint) do |config|
  config.fail_on_warnings = true
  # Don't want to run lint on upstream modules
  config.ignore_paths = ['vendor/**/*.pp', 'spec/**/*.pp', 'modules/**/*.pp']
end

desc 'Run syntax, lint, metadata and spec tests.'
task :test => [
  :syntax,
  :lint,
  :metadata_lint,
  :spec,
  :rubocop,
]
