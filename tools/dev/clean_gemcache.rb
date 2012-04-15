#!/usr/bin/env ruby

require 'fileutils'

base = ::File.expand_path(::File.join(::File.dirname(__FILE__), "..", "..", "lib", "gemcache"))
Dir.glob("#{base}/**/cache/*.gem").each do |gem|
	::FileUtils.rm_rf(gem)
end
