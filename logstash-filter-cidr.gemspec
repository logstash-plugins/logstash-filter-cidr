Gem::Specification.new do |s|

  s.name            = 'logstash-filter-cidr'
  s.version         = '0.1.1'
  s.licenses        = ['Apache License (2.0)']
  s.summary         = "The CIDR filter is for checking IP addresses in events against a list of network blocks that might contain it."
  s.description     = "The CIDR filter is for checking IP addresses in events against a list of network blocks that might contain it. Multiple addresses can be checked against multiple networks, any match succeeds. Upon success additional tags and/or fields can be added to the event."
  s.authors         = ["Elasticsearch"]
  s.email           = 'richard.pijnenburg@elasticsearch.com'
  s.homepage        = "http://logstash.net/"
  s.require_paths = ["lib"]

  # Files
  s.files = `git ls-files`.split($\)+::Dir.glob('vendor/*')

  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency 'logstash', '>= 1.4.0', '< 2.0.0'

end

