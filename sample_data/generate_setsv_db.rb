require_relative 'soundweb'

# Generate volume fader changes.
transmit [
  message([DI_SETSV, *hiqnet_address.to_a, *pack_db(0)]),     #   0.0 dB
  message([DI_SETSV, *hiqnet_address.to_a, *pack_db(5)]),     #   5.0 dB
  message([DI_SETSV, *hiqnet_address.to_a, *pack_db(10.5)]),  #  10.5 dB
  message([DI_SETSV, *hiqnet_address.to_a, *pack_db(-20)]),   # -20.0 dB
  message([DI_SETSV, *hiqnet_address.to_a, *pack_db(-55.7)]), # -55.7 dB
]

puts "Done."
