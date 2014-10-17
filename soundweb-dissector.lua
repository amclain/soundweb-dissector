--------------------------------------------------------------------------------
-- BSS Soundweb London Wireshark Dissector
--------------------------------------------------------------------------------
-- London Architect available from:
-- http://www.bssaudio.co.uk/en-US/softwares
-- 
-- Protocol document: "London DI Kit.pdf"
-- C:\Program Files (x86)\Harman Pro\London Architect\London DI Kit.pdf
-- 
-- Thanks to Peter Zotov and Robert G. Jakabosky for publishing their ZMTP
-- dissector source code, which was used as a foundation for this dissector.
-- https://github.com/whitequark/zmtp-wireshark
--------------------------------------------------------------------------------
-- The MIT License (MIT)

-- Copyright (c) 2014 Alex McLain

-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:

-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.

-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
-- THE SOFTWARE.
--------------------------------------------------------------------------------

-- cache globals to local for speed.
local format   = string.format
local tostring = tostring
local tonumber = tonumber
local pairs    = pairs

-- wireshark API globals
local Pref           = Pref
local Proto          = Proto
local ProtoField     = ProtoField
local DissectorTable = DissectorTable
local ByteArray      = ByteArray
local PI_MALFORMED   = PI_MALFORMED
local PI_ERROR       = PI_ERROR

-- declare protocol
local soundweb_proto = Proto("soundweb", "Soundweb", "BSS Soundweb London Protocol")

-- setup preferences
soundweb_proto.prefs["tcp_port_start"] =
    Pref.string("TCP port range start", "1023", "First TCP port to decode as this protocol")
soundweb_proto.prefs["tcp_port_end"] =
    Pref.string("TCP port range end", "1023", "Last TCP port to decode as this protocol")
soundweb_proto.prefs["protocol"] =
    Pref.string("Encapsulated protocol", "", "Subdissector to invoke")

-- current preferences settings.
local current_settings = {
    tcp_port_start = -1,
    tcp_port_end = -1,
    protocol = "",
}

-- setup protocol fields.
soundweb_proto.fields = {}
local fds = soundweb_proto.fields

fds.start_byte     = ProtoField.new("Start Byte", "soundweb.start_byte", ftypes.UINT8, nil, base.HEX)
fds.end_byte       = ProtoField.new("End Byte", "soundweb.end_byte", ftypes.UINT8, nil, base.HEX)
fds.hiqnet_address = ProtoField.new("HiQnet Address", "soundweb.hiqnet_address", ftypes.BYTES)
fds.command        = ProtoField.new("Command", "soundweb.command", ftypes.UINT8, nil, base.HEX)
fds.node           = ProtoField.new("Node", "soundweb.node", ftypes.UINT16, nil, base.HEX)
fds.virtual_device = ProtoField.new("Virtual Device", "soundweb.virtual_device", ftypes.UINT8, nil, base.HEX)
fds.object         = ProtoField.new("Object", "soundweb.object", ftypes.UINT24, nil, base.HEX)
fds.state_variable = ProtoField.new("State Variable", "soundweb.state_variable", ftypes.UINT16, nil, base.HEX)
fds.data           = ProtoField.new("Data", "soundweb.data", ftypes.UINT32, nil, base.HEX_DEC)
fds.checksum       = ProtoField.new("Checksum", "soundweb.checksum", ftypes.UINT8, nil, base.HEX)

local tcp_stream_id = Field.new("tcp.stream")
local subdissectors = DissectorTable.new("soundweb.protocol", "Soundweb", ftypes.STRING)

-- un-register tcp port range
local function unregister_tcp_port_range(start_port, end_port)
    if not start_port or start_port <= 0 or not end_port or end_port <= 0 then
        return
    end
    local tcp_port_table = DissectorTable.get("tcp.port")
    for port = start_port, end_port do
        tcp_port_table:remove(port, soundweb_proto)
    end
end

-- register tcp port range
local function register_tcp_port_range(start_port, end_port)
    if not start_port or start_port <= 0 or not end_port or end_port <= 0 then
        return
    end
    local tcp_port_table = DissectorTable.get("tcp.port")
    for port = start_port, end_port do
        tcp_port_table:add(port, soundweb_proto)
    end
end

-- handle preferences changes.
function soundweb_proto.init(arg1, arg2)
    local old_start, old_end
    local new_start, new_end
    -- check if preferences have changed.
    for pref_name,old_v in pairs(current_settings) do
        local new_v = soundweb_proto.prefs[pref_name]
        if new_v ~= old_v then
            if pref_name == "tcp_port_start" then
                old_start = old_v
                new_start = new_v
            elseif pref_name == "tcp_port_end" then
                old_end = old_v
                new_end = new_v
            end
            -- save new value.
            current_settings[pref_name] = new_v
        end
    end
    -- un-register old port range
    if old_start and old_end then
        unregister_tcp_port_range(tonumber(old_start), tonumber(old_end))
    end
    -- register new port range.
    if new_start and new_end then
        register_tcp_port_range(tonumber(new_start), tonumber(new_end))
    end
end

function soundweb_proto.dissector(tvb, pinfo, tree)
    local offset = 0
    local soundweb_frames
    local tap  = {}
    local desc = {}
    
    tap.mechanism = ""
    tap.frames = 0
    tap.commands = 0
    tap.messages = 0
    tap.body_bytes = 0
    
    function get_escaped_data(param, len)
        local starting_offset = offset
        local data = ByteArray.new()
        local byte = 0
        
        while len > 0 do
            byte = tvb(offset, 1):uint()
            
            if byte == 0x1B then
                offset = offset + 1
                byte = tvb(offset, 1):uint() - 0x80
            end
            
            data:append(ByteArray.new(byte))
            
            offset = offset + 1
            len = len - 1
        end
        
        -- TODO: Figure out how to determine value type.
        -- soundweb_frames:add(param, tvb(starting_offset, offset - starting_offset), data:tvb()():uint())
        soundweb_frames:add(param, tvb(starting_offset, offset - starting_offset))
        
        return data
    end
    
    -- print(format("soundweb_proto.dissector: offset:%d len:%d reported_len:%d", offset, tvb:len(), tvb:reported_len()), tvb(offset, 5))
    
    if not soundweb_frames then
        soundweb_frames = tree:add(soundweb_proto, tvb())
    end
    
    soundweb_frames:set_text(format("BSS Soundweb London Protocol"))
    
    get_escaped_data(fds.start_byte, 1)
    -- --------------------------------------
    -- TODO: Check for valid start byte: 0x02
    -- --------------------------------------
    get_escaped_data(fds.command, 1)
    get_escaped_data(fds.node, 2)
    get_escaped_data(fds.virtual_device, 1)
    get_escaped_data(fds.object, 3)
    get_escaped_data(fds.state_variable, 2)
    get_escaped_data(fds.data, 4)
    get_escaped_data(fds.checksum, 1)
    get_escaped_data(fds.end_byte, 1)
    -- -- --------------------------------------
    -- -- TODO: Check for valid end byte: 0x03
    -- -- --------------------------------------
    
    -- Info column
    pinfo.cols.protocol = "Soundweb"
    pinfo.cols.info = table.concat(desc, "; ")
    -- pinfo.tap_data = tap

    -- return offset
end
