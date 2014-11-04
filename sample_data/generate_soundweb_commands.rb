# This script generates the following Soundweb London command packets:
DI_SETSV                  = 0x88
DI_SUBSCRIBESV            = 0x89
DI_UNSUBSCRIBESV          = 0x8A
DI_VENUE_PRESET_RECALL    = 0x8B
DI_PARAM_PRESET_RECALL    = 0x8C
DI_SETSVPERCENT           = 0x8D
DI_SUBSCRIBESVPERCENT     = 0x8E
DI_UNSUBSCRIBESVPERCENT   = 0x8F
DI_BUMPSVPERCENT          = 0x90


gem 'ionian', '~>0.6.10'
require 'ionian'
require 'ostruct'

SOUNDWEB_IP   = '10.0.5.30'
SOUNDWEB_PORT = 1023

# Special bytes.
# See "London DI Kit.pdf" page 4
SPECIAL_BYTES = [
  STX = 0x02,
  ETX = 0x03,
  ACK = 0x06,
  NAK = 0x15,
  ESC = 0x1B,
]

hiqnet_address = OpenStruct.new \
  node:           0x1002,
  virtual_device: 0x03,
  object:         0x000147,
  sv:             0x0000

hiqnet_address.define_singleton_method(:to_a) {
  [
    node >> 8 & 0xFF, node & 0xFF,
    virtual_device,
    object >> 16 & 0xFF, object >> 8 & 0xFF, object & 0xFF,
    sv >> 8 & 0xFF, sv & 0xFF
  ]
}

# Message Format
#   <message> = <STX> <body> <checksum byte> <ETX>
#   <checksum byte> is the exclusive OR of all the bytes in <body>, before substitution.
# 
# Message Body Format
#   <Body> =
#   <DI_SETSV> <node> <virtual_device> <object> <state_variable> <data>
#   <DI_SUBSCRIBESV> <node> <virtual_device> <object> <state_variable> <rate>
#   <DI_UNSUBSCRIBESV> <node> <virtual_device> <object> <state_variable> <0>
#   <DI_VENUE_PRESET_RECALL> <data> <DI_PARAM_PRESET_RECALL> <data>
#   <DI_SETSVPERCENT> <node> <virtual_device> <object> <state_variable> <percentage>
#   <DI_SUBSCRIBESVPERCENT> <node> <virtual_device> <object> <state_variable> <rate>
#   <DI_UNSUBSCRIBESVPERCENT> <node> <virtual_device> <object> <state_variable> <0>
#   <DI_BUMPSVPERCENT> <node> <virtual_device> <object> <state_variable> <+/-percentage>
# 
# @see "London DI Kit.pdf" page 5
def make_message body
  checksum = body.reduce(0) { |a, byte| a ^ byte }
  
  [
    STX,
    *(body + [checksum]).map { |byte|
      # Escape special bytes in a message.
      # @see "London DI Kit.pdf" page 4
      SPECIAL_BYTES.include?(byte) ? [ESC, byte + 0x80] : byte
    }.flatten,
    ETX
  ]
end

packets = [
  make_message([DI_SETSV, *hiqnet_address.to_a, 0x00, 0x00, 0x00, 0x00]), # 0dB
  make_message([DI_SUBSCRIBESV, *hiqnet_address.to_a, 0x64]), # 100ms
  make_message([DI_UNSUBSCRIBESV, *hiqnet_address.to_a, 0x00]),
  make_message([DI_VENUE_PRESET_RECALL, 0x04]), # Preset 4
  make_message([DI_PARAM_PRESET_RECALL, 0x05]), # Preset 5
  make_message([DI_SETSVPERCENT, *hiqnet_address.to_a, 0x00, 0x64, 0x00, 0x00]), # 100% (100 * 65536)
  make_message([DI_SUBSCRIBESVPERCENT, *hiqnet_address.to_a, 0x64]), # 100ms
  make_message([DI_UNSUBSCRIBESVPERCENT, *hiqnet_address.to_a, 0x00]),
  make_message([DI_BUMPSVPERCENT, *hiqnet_address.to_a, 0x00, 0x64, 0x00, 0x00]), # 100%
]

Ionian::Socket.new host: "#{SOUNDWEB_IP}:#{SOUNDWEB_PORT}" do |socket|
  packets.each do |packet|
    socket.write packet.pack(packet.map { 'C' }.join)
    socket.flush
    sleep 0.1
  end
end

puts "Done."
