require_relative 'soundweb'

# Generate incorrect unsubscribe data value error.
transmit [
  message([DI_UNSUBSCRIBESV, *hiqnet_address.to_a, *pack_data(1)]),
  message([DI_UNSUBSCRIBESVPERCENT, *hiqnet_address.to_a, *pack_data(2)]),
]

puts "Done."
