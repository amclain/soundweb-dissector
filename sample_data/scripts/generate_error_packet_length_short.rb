require_relative 'soundweb'

# Generate short packet length errors.
transmit [
  message([*hiqnet_address.to_a, *pack_db(0)]),
  message([DI_SETSV, *pack_db(0)]),
  message([DI_SETSV, *hiqnet_address.to_a]),
  
  message([*pack_data(4)]),
  message([DI_VENUE_PRESET_RECALL]),
]

puts "Done."
