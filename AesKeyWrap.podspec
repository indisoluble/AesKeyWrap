Pod::Spec.new do |s|
  s.name             = 'AesKeyWrap'
  s.version          = '0.1.8'
  s.summary          = 'AES Key Wrap with Padding Algorithm (RFC 3394 & RFC 5649).'

  s.description      = <<-DESC
ObjC implementation of the AES Key Wrap with Padding Algorithm described in RFC 3394 & RFC 5649.
                       DESC

  s.homepage         = 'https://github.com/indisoluble/AesKeyWrap'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Enrique de la Torre' => 'indisoluble_dev@me.com' }
  s.source           = { :git => 'https://github.com/indisoluble/AesKeyWrap.git', :tag => s.version.to_s }

  s.ios.deployment_target = '8.0'

  s.source_files = 'AesKeyWrap/Classes/**/*'
end
