##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'PuTTY Add/Remove Trusted Host',
      'Description'   => %q{
        This module allows the attacker to add or remove a trusted host
        from PuTTY's store
      },
      'License'       => BSD_LICENSE,
      'Author'        => [ 'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptString.new('REMOTE_SSH_HOST', [ true, 'SSH server host to obtain fingerprint from.', '']),
      ], self.class)
  end


  def run
    begin
        Net::SSH.start(datastore['REMOTE_SSH_HOST'], "default") do |ssh|
            binding.pry
        end
    rescue
            binding.pry
    end 

  end

end
