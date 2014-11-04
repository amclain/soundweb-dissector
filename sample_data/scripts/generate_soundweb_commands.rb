require_relative 'soundweb'

# Generate each type of Soundweb command.
transmit [
  message([DI_SETSV, *hiqnet_address.to_a, 0x00, 0x00, 0x00, 0x00]), # 0dB
  message([DI_SUBSCRIBESV, *hiqnet_address.to_a, 0x64]), # 100ms
  message([DI_UNSUBSCRIBESV, *hiqnet_address.to_a, 0x00]),
  message([DI_VENUE_PRESET_RECALL, 0x04]), # Preset 4
  message([DI_PARAM_PRESET_RECALL, 0x05]), # Preset 5
  message([DI_SETSVPERCENT, *hiqnet_address.to_a, 0x00, 0x64, 0x00, 0x00]), # 100% (100 * 65536)
  message([DI_SUBSCRIBESVPERCENT, *hiqnet_address.to_a, 0x64]), # 100ms
  message([DI_UNSUBSCRIBESVPERCENT, *hiqnet_address.to_a, 0x00]),
  message([DI_BUMPSVPERCENT, *hiqnet_address.to_a, 0x00, 0x64, 0x00, 0x00]), # 100%
]

puts "Done."
