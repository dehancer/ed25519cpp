Pod::Spec.new do |s|

  s.name         = "ed25519"
  s.version      = "1.1.2"
  s.summary      = "ed25519 is a public-key signature system framework for swift"
  s.description  = "ed25519 features: Fast single-signature verification; fast batch verification; very fast signing; high security level; small size of keys and signatures"

  s.homepage     = "https://ed25519.cr.yp.to/"

  s.license      = { :type => "MIT", :file => "LICENSE" }
  s.authors            = { "denis svinarchuk" => "denn.nevera@gmail.com" }
  s.social_media_url   = "https://mile.global"

  s.platform     = :ios
  s.platform     = :osx

  s.ios.deployment_target = "11.0"
  s.osx.deployment_target = "10.14"
 
  s.swift_version = "4.2"

  s.source       = { :git => "https://bitbucket.org/mile-core/mile-cpp-api", :tag => "#{s.version}" }

  s.source_files  = "platforms/swift/sdk/Classes/*.{h,m,mm}",
                    "src/*.cpp",
                    "src/external/*.{cpp,hpp}",
                    "include/**/*.hpp",
                    "external/ed25519/src/*.{c,h}",
                    "external/ed25519/include/*.{h}"
                    
  s.exclude_files = "test", "docs", "build", "cmake-build-debug"

  s.public_header_files = "platforms/swift/sdk/Classes/*.{h,hpp}"

  s.frameworks = "Foundation"
  s.libraries  = 'c++'

  s.requires_arc = true
  s.compiler_flags = '-Wno-format', '-x objective-c++', '-DNDEBUG', '-DUSE_DEC_FIXEDPOINT', '-DR128_STDC_ONLY'
  
  s.xcconfig = { 'GCC_PREPROCESSOR_DEFINITIONS' => 'CSA=1' , 'OTHER_CFLAGS' => '',
                 'HEADER_SEARCH_PATHS' => '"/usr/local/include" "${PODS_ROOT}" "${PODS_ROOT}/src" "${PODS_ROOT}/../../../src"  "${PODS_ROOT}/../../ed25519cpp/src"',
                    'CLANG_CXX_LANGUAGE_STANDARD' => 'c++17',
                    'CLANG_CXX_LIBRARY' => 'libc++'}
  
end
