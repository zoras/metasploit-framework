#
# This handles gem requirements for bundled installer environments
#

module Msf
module Env
class Gemcache

	@@msfbase = ::File.expand_path(::File.join(::File.dirname(__FILE__), '..', '..', '..'))
	@@gembase = ::File.join(@@msfbase, "lib/gemcache")
	@@gemarch = ( RUBY_PLATFORM =~ /mingw/ ? 'win32' : ( RUBY_PLATFORM =~ /x86_64.*linux/ ? 'linux64' : (RUBY_PLATFORM =~ /i\d86.*linux/ ? 'linux32' : 'unknown') ) )
	@@rubvers =	RUBY_VERSION =~ /^(1\.9\.|2\.)/ ? '1.9.1' : RUBY_VERSION
	
	def self.configure
		return if not ::File.exist?(@@gembase)
		
		# The gemcache directory is a modified version of the output created by
		# $ bundle install --path=lib/gemcache from within the Pro environment
		
		::Dir["#{@@gembase}/ruby/#{@@rubvers}/gems/*/lib"].each { |lib| $:.unshift(lib) }		
		::Dir["#{@@gembase}/ruby/#{@@rubvers}/arch/#{@@gemarch}/*/lib"].each { |lib| $:.unshift(lib) }
	end



end
end
end


Msf::Env::Gemcache.configure
