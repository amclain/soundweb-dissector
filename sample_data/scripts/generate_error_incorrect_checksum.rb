require_relative 'soundweb'

# Generate checksum error.
transmit [
  message([DI_SETSV, *hiqnet_address.to_a, *pack_db(0)]).tap { |packet| packet[-2] = 0x01 }
]

puts "Done."
