-- Sample conf file, applying the profinet inspector

-- Use rules from the myrules.rules file

ips = { include = 'myrule.rules' }

profinet =
{
--    param1 = 'value1',
--    param2 = 23
}

binder =
{
  {when = { proto = 'udp', ports = '1566' }, use = { type = 'profinet' }, },
--    {when = { proto = 'udp', ports = '1566' } },

  {use = { action = 'allow' } },
  
}