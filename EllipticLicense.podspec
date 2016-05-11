Pod::Spec.new do |s|

s.name         = "EllipticLicense"
s.version      = "0.1.1"
s.summary      = "Short product key generation and validation framework based on elliptic curves digital signatures (ECDSA). for Mac OS X/Cocoa."

s.homepage     = "https://github.com/vslavik/ellipticlicense"
s.license      = { :type => "MIT", :file => "LICENSE" }

s.author       = { "Václav Slavík" => "vaclav@slavik.io" }

s.platform     = :osx, "10.7"
s.osx.deployment_target = "10.7"
s.source       = { :git => "https://github.com/vslavik/ellipticlicense.git", :tag => "v0.1.1" }

s.source_files = "Framework/*.{h,m}", "c_api/*.{h,c}"

s.frameworks   = "Cocoa"

s.requires_arc = true
s.xcconfig     = { 'OTHER_LDFLAGS' => '-lObjC'}

end
