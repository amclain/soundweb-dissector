require_relative 'soundweb'

# Generate short packet length errors.
transmit [
  message([*hiqnet_address.to_a, *pack_db(0)]),                             # Missing command.
  message([DI_SETSV, *pack_db(0)]),                                         # Missing HiQnet address.
  message([DI_SETSV, *hiqnet_address.to_a[0..-2], *pack_data(0x1F2F3F4F)]), # Missing state variable.
  message([DI_SETSV, *hiqnet_address.to_a]),                                # Missing data.
  
  message([*pack_data(4)]),          # Missing command.
  message([DI_VENUE_PRESET_RECALL]), # Missing data.
  
  [0x02], # No command.
  [0x00], # Invalid start byte.
]

puts "Done."
