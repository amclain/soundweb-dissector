require_relative 'soundweb'

# Generate volume fader changes.
transmit [
  message([DI_SETSVPERCENT, *hiqnet_address.to_a, *pack_percent(0)]),
  message([DI_SETSVPERCENT, *hiqnet_address.to_a, *pack_percent(100)]),
  message([DI_SETSVPERCENT, *hiqnet_address.to_a, *pack_percent(50)]),
  message([DI_SETSVPERCENT, *hiqnet_address.to_a, *pack_percent(20.5)]),
  message([DI_SETSVPERCENT, *hiqnet_address.to_a, *pack_percent(-10.75)]),
]

puts "Done."
