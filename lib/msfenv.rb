#
# Shim load the bundled gem cache if the environment is set
#

# If the bundle option is explicitly set, load the gemcache
if ENV['MSF_BUNDLE_GEMS'].to_s.downcase =~ /^[yt1]/
	require 'msf/env/gemcache'
else
	# If the bundle option is empty and this looks like an installer environment
	# also load the gem cache (but probably not the binary gem cache)
	if ENV['MSF_BUNDLE_GEMS'].to_s.length == 0 and 
		::File.exists?( File.join( File.dirname(__FILE__), "..", "..", "properties.ini") ) and
		::File.directory?( File.join( File.dirname(__FILE__), "..", "..", "apps", "pro") )
			require 'msf/env/gemcache'
	end
end

	
