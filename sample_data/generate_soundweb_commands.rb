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

SOUNDWEB_IP   = '10.0.5.30'
SOUNDWEB_PORT = 1023

# Special bytes.
# See "London DI Kit.pdf" page 4
STX = 0x02
ETX = 0x03
ACK = 0x06
NAK = 0x15
ESC = 0x1B

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
  [
    STX,
    *body,
    body.reduce(0) { |a, byte| a ^ byte }, # Checksum
    ETX
  ]
end

packets = [
  make_message([DI_SETSVPERCENT, 0x10, 0x1B, 0x82, 0x1B, 0x83, 0x00, 0x01, 0x47, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00])
]

Ionian::Socket.new host: "#{SOUNDWEB_IP}:#{SOUNDWEB_PORT}" do |socket|
  packets.each do |packet|
    socket.write packet.pack(packet.map { 'C' }.join)
    socket.flush
  end
end
