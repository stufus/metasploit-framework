##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post
  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Windows Pageant Detector',
                      'Description'   => %q{
                        This module searches for instances of Pageant (part of PuTTY) and will
                        inform you whether it is running or not in the context of the user running
                        meterpreter.
                      },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>' ],
                      'Platform'      => [ 'win' ],
                      'Arch'          => [ 'x86', 'x64' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
  end

  # Main method
  def run
    hwnd = client.railgun.user32.FindWindowW("Pageant", "Pageant")
    if hwnd['return'] == 0
      print_error "Pageant not found"
    else
      print_good "Pageant is running (Handle: #{hwnd['return']})"
    end
  end
end
