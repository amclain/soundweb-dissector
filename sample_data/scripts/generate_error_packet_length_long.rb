require_relative 'soundweb'

# Generate long packet length errors.
transmit [
  message([DI_SETSV, *hiqnet_address.to_a, *pack_db(0), 0x01]),
  message([DI_SETSV, *hiqnet_address.to_a, *pack_db(0)]) + [0x01],
  message([DI_SETSV, *hiqnet_address.to_a, *pack_db(0)]) + [0x01, 0x02, 0x03, 0x04],
  [0x01, 0x02, 0x03, 0x04] + message([DI_SETSV, *hiqnet_address.to_a, *pack_db(0)]),
  
  message([DI_VENUE_PRESET_RECALL, *pack_data(4), 0x01]),
  message([DI_VENUE_PRESET_RECALL, *pack_data(4)]) + [0x01],
  message([DI_VENUE_PRESET_RECALL, *pack_data(4)]) + [0x01, 0x02, 0x03, 0x04],
  [0x01, 0x02, 0x03, 0x04] + message([DI_VENUE_PRESET_RECALL, *pack_data(4)]),
]

puts "Done."
