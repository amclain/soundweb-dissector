require_relative 'soundweb'

# Generate each type of Soundweb command.
transmit [
  message([DI_SETSV, *hiqnet_address.to_a, *pack_db(0)]), # 0dB
  message([DI_SUBSCRIBESV, *hiqnet_address.to_a, *pack_data(100)]), # 100ms
  message([DI_UNSUBSCRIBESV, *hiqnet_address.to_a, *pack_data(0)]),
  message([DI_VENUE_PRESET_RECALL, *pack_data(4)]), # Preset 4
  message([DI_PARAM_PRESET_RECALL, *pack_data(5)]), # Preset 5
  message([DI_SETSVPERCENT, *hiqnet_address.to_a, *pack_percent(100)]), # 100% (100 * 65536)
  message([DI_SUBSCRIBESVPERCENT, *hiqnet_address.to_a, *pack_data(100)]), # 100ms
  message([DI_UNSUBSCRIBESVPERCENT, *hiqnet_address.to_a, *pack_data(0)]),
  message([DI_BUMPSVPERCENT, *hiqnet_address.to_a, *pack_percent(100)]), # 100%
]

puts "Done."
