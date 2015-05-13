# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/mimikatz/tlv'

module Post
module Meterpreter
module Extensions
module PageantJacker

###
#
# Mimikatz extension - grabs credentials from windows memory.
#
# Benjamin DELPY `gentilkiwi`
# http://blog.gentilkiwi.com/mimikatz
#
# extension converted by Ben Campbell (Meatballs)
###

class Mimikatz < Extension

  def initialize(client)
    super(client, 'mimikatz')

    client.register_extension_aliases(
      [
        {
          'name' => 'mimikatz',
          'ext'  => self
        },
      ])
  end

  def send_pageant_request(function, args=[])
    request = Packet.create_request('mimikatz_custom_command')
    request.add_tlv(TLV_TYPE_MIMIKATZ_FUNCTION, function)
    request.add_tlv(TLV_TYPE_MIMIKATZ_FUNCTION, function)
    response = client.send_request(request)
    return response.get_tlv_value(TLV_TYPE_MIMIKATZ_RESULT)
  end

  def start_listening
    # check_pageant

    # open thread { 
       # when data in
         # send_pageant_request
       #
    # }

  end

  def stop_listening
  end

end

end; end; end; end; end

