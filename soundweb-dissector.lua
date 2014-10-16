---------------------------------------------
-- BSS Soundweb London Wireshark Dissector --
---------------------------------------------

-- cache globals to local for speed.
local format   = string.format
local tostring = tostring
local tonumber = tonumber
local sqrt     = math.sqrt
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

local stream_mechanisms = {}

function soundweb_proto.dissector(tvb, pinfo, tree)
    local offset = 0
    local rang
    local soundweb_frames
    local tap  = {}
    local desc = {}
    
    tap.mechanism = ""
    tap.frames = 0
    tap.commands = 0
    tap.messages = 0
    tap.body_bytes = 0
    
    -- print(format("soundweb_proto.dissector: offset:%d len:%d reported_len:%d", offset, tvb:len(), tvb:reported_len()), tvb(offset, 5))
    
    if not soundweb_frames then
        soundweb_frames = tree:add(soundweb_proto, tvb())
    end
    
    soundweb_frames:set_text(format("BSS Soundweb London Protocol"))
    
    soundweb_frames:add(fds.start_byte, tvb(0, 1))
    soundweb_frames:add(fds.command, tvb(1, 1))
    soundweb_frames:add(fds.node, tvb(2, 2))
    soundweb_frames:add(fds.virtual_device, tvb(4, 1))
    soundweb_frames:add(fds.object, tvb(5, 3))
    soundweb_frames:add(fds.state_variable, tvb(8, 2))
    soundweb_frames:add(fds.data, tvb(10, 4))
    soundweb_frames:add(fds.checksum, tvb(14, 1))
    soundweb_frames:add(fds.end_byte, tvb(15, 1))
    
    -- Info column
    pinfo.cols.protocol = "Soundweb"
    pinfo.cols.info = table.concat(desc, "; ")
    -- pinfo.tap_data = tap
    
    -- return offset
end
