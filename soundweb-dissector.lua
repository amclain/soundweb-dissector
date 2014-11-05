--------------------------------------------------------------------------------
-- BSS Soundweb London Wireshark Dissector
-- v0.1.0
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
local abs      = math.abs
local floor    = math.floor

-- wireshark API globals
local Pref           = Pref
local Proto          = Proto
local ProtoField     = ProtoField
local DissectorTable = DissectorTable
local ByteArray      = ByteArray
local PI_MALFORMED   = PI_MALFORMED
local PI_ERROR       = PI_ERROR

-- Soundweb Command Bytes
local DI_SETSV                = 0x88
local DI_SUBSCRIBESV          = 0x89
local DI_UNSUBSCRIBESV        = 0x8A
local DI_VENUE_PRESET_RECALL  = 0x8B
local DI_PARAM_PRESET_RECALL  = 0x8C
local DI_SETSVPERCENT         = 0x8D
local DI_SUBSCRIBESVPERCENT   = 0x8E
local DI_UNSUBSCRIBESVPERCENT = 0x8F
local DI_BUMPSVPERCENT        = 0x90

-- declare protocol
local soundweb_proto = Proto("soundweb", "BSS Soundweb London Protocol")

-- setup preferences
soundweb_proto.prefs["tcp_port"] =
    Pref.string("TCP Port", "1023", "TCP port to decode as this protocol.")
soundweb_proto.prefs["protocol"] =
    Pref.string("Encapsulated protocol", "", "Subdissector to invoke")

-- current preferences settings.
local current_settings = {
    tcp_port = -1,
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
fds.data           = ProtoField.new("Data", "soundweb.data", ftypes.INT32, nil, base.DEC)
fds.checksum       = ProtoField.new("Checksum", "soundweb.checksum", ftypes.UINT8, nil, base.HEX)

local tcp_stream_id = Field.new("tcp.stream")
local subdissectors = DissectorTable.new("soundweb.protocol", "Soundweb", ftypes.STRING)

-- Handle preferences changes.
function soundweb_proto.init(arg1, arg2)
    local old_port, new_port
    
    -- Check if preferences have changed.
    for pref_name, old_val in pairs(current_settings) do
        local new_val = soundweb_proto.prefs[pref_name]
        if new_val ~= old_val then
            if pref_name == "tcp_port" then
                old_port = tonumber(old_val)
                new_port = tonumber(new_val)
            end
            -- Save new value.
            current_settings[pref_name] = new_val
        end
    end
    
    -- Update port change.
    local tcp_port_table = DissectorTable.get("tcp.port")
    if old_port and old_port > 0 then tcp_port_table:remove(old_port, soundweb_proto) end
    if new_port and new_port > 0 then tcp_port_table:add(new_port, soundweb_proto) end
end

-- SoundwebItem object

SoundwebItem = {}
SoundwebItem.__index = SoundwebItem

function SoundwebItem.new(param, field_len, tvb, data, starting_offset, ending_offset)
    local obj = {}
    setmetatable(obj, SoundwebItem)
    
    obj.__param = param
    obj.__field_len = field_len
    obj.__tvb = tvb   -- Raw tvb data with escape characters.
    obj.__data = data -- tvb of unescaped data (processed).
    obj.__starting_offset = starting_offset
    obj.__ending_offset = ending_offset
    obj.__description = ""
    
    return obj
end

function SoundwebItem:param()
    return self.__param
end

function SoundwebItem:tvb()
    return self.__tvb
end

function SoundwebItem:data()
    return self.__data
end

function SoundwebItem:field_len()
    return self.__field_len
end

function SoundwebItem:starting_offset()
    return self.__starting_offset
end

function SoundwebItem:ending_offset()
    return self.__ending_offset
end

function SoundwebItem:description()
    return self.__description
end

function SoundwebItem:set_description(text)
    self.__description = text
end

function SoundwebItem:has_description(text)
    return string.len(self.__description) > 0
end

function SoundwebItem:add_to_tree(tree)
    return tree:add(self:param(), self:tvb(), self:data():uint())
end

-- End SoundwebItem object

function round (value, precision)
    local shift = 10 ^ precision
    return floor(value * shift + 0.5) / shift
end

-- bxor algorithm by phoog
-- http://stackoverflow.com/questions/5977654/lua-bitwise-logical-operations
function bxor (a,b)
  local r = 0
  for i = 0, 31 do
    local x = a / 2 + b / 2
    if x ~= floor (x) then
      r = r + 2^i
    end
    a = floor (a / 2)
    b = floor (b / 2)
  end
  return r
end

function soundweb_proto.dissector(tvb, pinfo, tree)
    local offset = 0
    local items = {}
    local trees = {}
    local desc = {}
    
    function get_soundweb_item(param, len)
        local starting_offset = offset
        local data = ByteArray.new()
        local byte = nil
        local do_escape = false
        
        while len > 0 do
            do_escape = false
            byte = tvb(offset, 1)
            
            -- Detect escape byte.
            if byte:uint() == 0x1B then
                do_escape = true
                offset = offset + 1
                byte = tvb(offset, 1)
            end
            
            data:append(byte:bytes())
            
            -- Process escape byte.
            if do_escape == true then
                do_escape = false
                local i = data:len() - 1
                data:set_index(i, data:get_index(i) - 0x80)
            end
            
            offset = offset + 1
            len = len - 1
        end
        
        return SoundwebItem.new(param, len, tvb(starting_offset, offset - starting_offset), data:tvb()(), starting_offset, offset)
    end
    
    trees.soundweb = tree:add(soundweb_proto, tvb())
    
    items.start_byte = get_soundweb_item(fds.start_byte, 1)
    trees.start_byte = items.start_byte:add_to_tree(trees.soundweb)
    
    -- Check for valid start byte: 0x02
    if items.start_byte:data():uint() == 0x02 then
        trees.start_byte:append_text(" (STX)")
    else
        trees.start_byte:append_text(" (Expected 0x02 STX)")
        trees.start_byte:add_expert_info(PI_PROTOCOL, PI_ERROR, "Expected start byte value 0x02")
    end
    
    items.command = get_soundweb_item(fds.command, 1)
    trees.command = items.command:add_to_tree(trees.soundweb)
    
    local command_byte = items.command:data():uint()
    if     command_byte == DI_SETSV                then items.command:set_description("SETSV")
    elseif command_byte == DI_SUBSCRIBESV          then items.command:set_description("SUBSCRIBESV")
    elseif command_byte == DI_UNSUBSCRIBESV        then items.command:set_description("UNSUBSCRIBESV")
    elseif command_byte == DI_VENUE_PRESET_RECALL  then items.command:set_description("VENUE_PRESET_RECALL")
    elseif command_byte == DI_PARAM_PRESET_RECALL  then items.command:set_description("PARAM_PRESET_RECALL")
    elseif command_byte == DI_SETSVPERCENT         then items.command:set_description("SETSVPERCENT")
    elseif command_byte == DI_SUBSCRIBESVPERCENT   then items.command:set_description("SUBSCRIBESVPERCENT")
    elseif command_byte == DI_UNSUBSCRIBESVPERCENT then items.command:set_description("UNSUBSCRIBESVPERCENT")
    elseif command_byte == DI_BUMPSVPERCENT        then items.command:set_description("BUMPSVPERCENT")
    end
    
    if items.command:has_description() then
        trees.command:append_text(" (" .. items.command:description() .. ")")
    end
    
    if command_byte ~= DI_VENUE_PRESET_RECALL and command_byte ~= DI_PARAM_PRESET_RECALL then
        items.node = get_soundweb_item(fds.node, 2)
        items.virtual_device = get_soundweb_item(fds.virtual_device, 1)
        items.object = get_soundweb_item(fds.object, 3)
        
        -- ----------------------------------------------------------
        -- TODO: Should highlight HiQnet address range when selected.
        -- ----------------------------------------------------------
        trees.address = trees.soundweb:add("HiQnet Address: ", tvb(items.node:starting_offset(), items.object:ending_offset() - items.node:starting_offset()))
        trees.node = items.node:add_to_tree(trees.address)
        trees.virtual_device = items.virtual_device:add_to_tree(trees.address)
        trees.object = items.object:add_to_tree(trees.address)
        
        items.state_variable = get_soundweb_item(fds.state_variable, 2)
        trees.state_variable = items.state_variable:add_to_tree(trees.soundweb)
    end
    
    items.data = get_soundweb_item(fds.data, 4)
    trees.data = items.data:add_to_tree(trees.soundweb)
    
    items.checksum = get_soundweb_item(fds.checksum, 1)
    trees.checksum = items.checksum:add_to_tree(trees.soundweb)
    
    local checksum_bytes = ByteArray.new()
    checksum_bytes:append(items.command:data():bytes())
    if command_byte ~= DI_VENUE_PRESET_RECALL and command_byte ~= DI_PARAM_PRESET_RECALL then
        checksum_bytes:append(items.node:data():bytes())
        checksum_bytes:append(items.virtual_device:data():bytes())
        checksum_bytes:append(items.object:data():bytes())
        checksum_bytes:append(items.state_variable:data():bytes())
    end
    checksum_bytes:append(items.data:data():bytes())
    
    local expected_checksum = 0x00
    for i = 0, checksum_bytes:len() - 1 do
        expected_checksum = bxor(expected_checksum, checksum_bytes:get_index(i))
    end
    
    if items.checksum:data():uint() ~= expected_checksum then
        trees.checksum:append_text(format(" (expected 0x%x)", expected_checksum))
        trees.checksum:add_expert_info(PI_PROTOCOL, PI_ERROR, format("Invalid checksum. Expected 0x%x", expected_checksum))
    end
    
    items.end_byte = get_soundweb_item(fds.end_byte, 1)
    trees.end_byte = items.end_byte:add_to_tree(trees.soundweb)
    
    -- Add labels
    if command_byte ~= DI_VENUE_PRESET_RECALL and command_byte ~= DI_PARAM_PRESET_RECALL then
        local hiqnet_address_text = "0x" .. tostring(items.node:data()) .. tostring(items.virtual_device:data()) .. tostring(items.object:data())
        trees.address:append_text(hiqnet_address_text)
        trees.soundweb:append_text(", HiQnet Address: " .. hiqnet_address_text)
        table.insert(desc, "HiQnet Address=" .. hiqnet_address_text)
        
        trees.soundweb:append_text(", SV: 0x" .. tostring(items.state_variable:data()))
        table.insert(desc, "SV=0x" .. tostring(items.state_variable:data()))
    end
    
    trees.soundweb:append_text(", Cmd: 0x" .. tostring(items.command:data()))
    if items.command:has_description() then
        trees.soundweb:append_text(" (" .. tostring(items.command:description() .. ")"))
    end
    table.insert(desc, "Cmd=" .. tostring(items.command:description()))
    
    if command_byte == DI_SETSV then
        -- Append data as level in dB.
        local db_value = 0
        local data_value = items.data:data():int()
        
        if data_value > -10000 then
            db_value = data_value / 10000
        else
            db_value = -10 * (10 ^ (abs(data_value + 100000) / 200000))
        end
        
        trees.data:append_text(" (" .. tostring(round(db_value, 2)) .. " dB)")
    elseif command_byte == DI_SETSVPERCENT or command_byte == DI_BUMPSVPERCENT then
        -- Append data as percent.
        trees.data:append_text(" (" .. tostring(round(items.data:data():int() / 65536, 2)) .. "%)")
    elseif command_byte == DI_SUBSCRIBESV or command_byte == DI_SUBSCRIBESVPERCENT then
        -- Append data as rate in milliseconds.
        trees.data:append_text(" (" .. tostring(items.data:data():int()) .. " ms)")
        trees.soundweb:append_text(", Rate: " .. tostring(items.data:data():int()) .. "ms")
        table.insert(desc, "Rate=" .. tostring(items.data:data():int()) .. "ms")
    elseif command_byte == DI_UNSUBSCRIBESV or command_byte == DI_UNSUBSCRIBESVPERCENT then
        if items.data:data():int() == 0 then
            trees.data:append_text(" (unsubscribe)")
        end
    elseif command_byte == DI_VENUE_PRESET_RECALL or command_byte == DI_PARAM_PRESET_RECALL then
        -- Append data as preset number.
        trees.soundweb:append_text(", Preset: " .. tostring(items.data:data():int()))
        table.insert(desc, "Preset=" .. tostring(items.data:data():int()))
    end
    
    -- Check for valid end byte: 0x03
    if items.end_byte:data():uint() == 0x03 then
        trees.end_byte:append_text(" (ETX)")
    else
        trees.end_byte:append_text(" (Expected 0x03 ETX)")
        trees.end_byte:add_expert_info(PI_PROTOCOL, PI_ERROR, "Expected end byte value 0x03")
    end
    
    -- Info column
    pinfo.cols.protocol = "Soundweb"
    pinfo.cols.info = table.concat(desc, " ")
    
    -- Return the number of bytes consumed from tvb.
    return offset
end
