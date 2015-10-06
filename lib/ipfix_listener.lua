local fiber     = require("fiber")
local socket    = require("socket")
local ipfix     = require("ipfix")
local constants = require("constants")

local proto = constants.proto

local _M = { config = {} }

_M.set_config = function(config)
    _M.config = config
end


local ipfix_listener = function(port,channel)

    -- Set fiber listener name
    local self = fiber.self()
    self:name("ipfix/listener-port-" .. port)

    -- Bind to _M.configured ports
    local sock = socket("AF_INET","SOCK_DGRAM", "udp")
    sock:setsockopt(proto.UDP,"SO_REUSEADDR",true)
    sock:bind("0.0.0.0",port)

    local max_flow_packet_length = _M.config.max_flow_packet_length

    while 1 == 1 do
        -- Wait until socket has data to read
        sock:readable()
        local packet, sa = sock:recvfrom(max_flow_packet_length)
        if packet then -- No packets ready to be received - do nothing

            -- Parse recieved packet header
            local header, packet = ipfix.parse_header(packet)

            -- Make sure this parses correctly as a V10 packet, otherwise skip
            if header.ver == 10 then
                -- Parse packet sets while we still have some
                while #packet > 0 do
                    
                    set, packet = ipfix.parse_set(packet)

                    if set.id ~= 2 and set.id ~= 3 then
                        local new_flows = set.flows
                        -- If we have new flows, then 
                        if new_flows then
                            for i=1,#new_flows do

                                local channel_count = channel:count()

                                -- If channel is full then cache flows here and attempt submission later
                                if channel:is_full() then
                                    lp.dequeue("DATA LOST - Fiber channel full. Please increase fiber_channel_capacity config setting",5)
                                else 
                                    if channel_count > (_M.config.fiber_channel_capacity * _M.config.fiber_channel_full_perc) then
                                        lp.dequeue("Fiber channel is almost full! Please check your fiber_channel_capacity setting",5)
                                    end
                                    local flow = new_flows[i]
                                    if not channel:put(flow,_M.config.fiber_channel_timeout) then
                                        lp.dequeue("Error submitting to fiber channel",5)
                                    end
                                end
                            end
                        end
                    end
                end
            end
        end
    end
end

_M.start = function(port,channel)
    return fiber.create(ipfix_listener,port,channel)
end

return _M
