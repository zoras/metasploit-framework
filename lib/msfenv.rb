#
# Shim load the bundled gem cache if the environment is set
#
require 'msf/env/gemcache' if ENV['MSF_BUNDLE_GEMS']
