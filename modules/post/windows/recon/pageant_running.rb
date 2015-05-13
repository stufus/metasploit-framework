##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows Pageant Enumeration',
      'Description'   => %q{
        This module searches for instances of Pageant (part of PuTTY) and will
        inform you whether it is running or not in the context of the user running
        meterpreter. 

        If Pageant is running, you may wish to load PageantJacker to allow you to
        proxy connections between your host and the remote Pageant. This recon module
        is really here to help you decide whether to load the extension or not; if
        Pageant is not running, there is no point in doing so.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>' ],
      'Platform'      => [ 'win' ],
      'Arch'          => [ 'x86', 'x64' ],
      'SessionTypes'  => [ 'meterpreter' ],
    ))
  end

  # Main method
  def run
    hwnd = client.railgun.user32.FindWindowW("Pageant", "Pageant")
    if hwnd['return'] == 0
        print_error "Pageant not found"
    else
        print_status "Pageant is running (Handle: #{hwnd['return']})"
    end
    return
  end

end
