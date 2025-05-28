Pod::Spec.new do |s|
  s.name         = 'TinfoilKit'
  s.version      = '0.0.5'
  s.summary      = 'Official Tinfoil Swift client'
  s.homepage     = 'https://github.com/tinfoilsh/tinfoil-swift'
  s.license      = { :type => 'GPL', :file => 'LICENSE' }
  s.authors      = { 'tinfoil' => 'contact@tinfoil.sh' }

  s.platform     = :ios, '17.0'
  s.swift_version = '5.9'
  s.source       = { :git => 'https://github.com/tinfoilsh/tinfoil-swift.git', :tag => s.version.to_s }

  s.source_files = 'Sources/TinfoilKit/**/*.swift'
  
  # Dependencies
  s.dependency 'OpenAIKit', '~> 1.0'
  
  # Binary framework dependency (TinfoilVerifier)
  s.vendored_frameworks = 'TinfoilVerifier.xcframework'
  
  s.static_framework = true
end