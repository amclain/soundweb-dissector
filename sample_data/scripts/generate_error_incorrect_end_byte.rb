require_relative 'soundweb'

# Generate end byte error.
transmit [
  message([DI_SETSV, *hiqnet_address.to_a, *pack_db(0)]).tap { |packet| packet[-1] = 0x01 }
]

puts "Done."
