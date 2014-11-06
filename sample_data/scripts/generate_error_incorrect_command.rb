require_relative 'soundweb'

# Generate incorrect command error.
transmit [
  message([0x01, *hiqnet_address.to_a, *pack_db(0)])
]

puts "Done."
