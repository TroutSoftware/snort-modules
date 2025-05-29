
serializer_csv =  { item_separator = " ",
                    if_item_blank_then_output = "-",
                  }

-- logger file output set from command line
logger_file = { serializer = 'serializer_csv' }

trout_wizard = { tag = 'NA',
                 inference = false,
                 logger = 'logger_file',
                 pack_data = false,
                 split_size = 253,
                 concatenate = true                 
               }

stream = {}
stream_icmp = {}
stream_tcp = {}
stream_udp = {}
stream_ip = {}

binder = {
  { use = {type = 'trout_wizard'} }
}               
