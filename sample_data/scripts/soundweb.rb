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

# Soundweb commands.
DI_SETSV                  = 0x88
DI_SUBSCRIBESV            = 0x89
DI_UNSUBSCRIBESV          = 0x8A
DI_VENUE_PRESET_RECALL    = 0x8B
DI_PARAM_PRESET_RECALL    = 0x8C
DI_SETSVPERCENT           = 0x8D
DI_SUBSCRIBESVPERCENT     = 0x8E
DI_UNSUBSCRIBESVPERCENT   = 0x8F
DI_BUMPSVPERCENT          = 0x90

# HiQnet address packet.
# Call #to_a to output its byte sequence.
def hiqnet_address
  address ||= OpenStruct.new(
    node:           0x1002,
    virtual_device: 0x03,
    object:         0x000147,
    sv:             0x0000
  ).tap do |o|
    o.define_singleton_method(:to_a) {
      [
        node >> 8 & 0xFF, node & 0xFF,
        virtual_device,
        object >> 16 & 0xFF, object >> 8 & 0xFF, object & 0xFF,
        sv >> 8 & 0xFF, sv & 0xFF
      ]
    }
  end
end

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
def message body
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

# Pack a value in dB into a series of Soundweb bytes.
def pack_db value
  [
    if value > -10
      value * 10000
    else
      (-Math.log10((value / 10).abs) * 200000) - 100000
    end
  ].pack('l>').split('').map(&:ord)
end

# Pack a value as a percent into a series of Soundweb bytes.
def pack_percent value
  [value * 65536].pack('l>').split('').map(&:ord)
end

# Transmit array of packets to Soundweb hardware.
def transmit packets, delay: 0.1
  Ionian::Socket.new host: "#{SOUNDWEB_IP}:#{SOUNDWEB_PORT}" do |socket|
    packets.each do |packet|
      socket.write packet.pack(packet.map { 'C' }.join)
      socket.flush
      sleep delay
    end
  end
end
