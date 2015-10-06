local os          = require("os")
local binutil     = require("binutil")
local ipfix       = require("ipfix")
local ip          = require("ip")
local math_ceil   = math.ceil
local math_floor  = math.floor
local lp          = require("logprint")

local util        = require("util")
local events      = require("events")
local constants   = require("constants")


local _M = { config = {} }

_M.set_config = function(config)
    _M.config = config
end


local ipfix_aggregator = function(ipfix_channel,aggregate_channel)
    -- Set fiber listener name
    local self = fiber.self()
    self:name("ipfix/aggregator")

    local decode_icmp_type = util.decode_icmp_type
    local decode_tcp_flags = util.decode_tcp_flags

    local status_active            = 1

    local spc_flows                = box.space.flows

    -- We normalise flows to seconds. Bucket length is in seconds
    local bucket_length            = _M.config.bucket_length
    local bucket_count             = _M.config.bucket_count
    local active_timeout           = _M.config.active_timeout
    local idle_timeout             = _M.config.idle_timeout

    local ebn = _M.config.elements.by_name
    local packetDeltaCount         = ebn.packetDeltaCount
    local octetDeltaCount          = ebn.octetDeltaCount
    local flowStartSeconds         = ebn.flowStartSeconds
    local flowEndSeconds           = ebn.flowEndSeconds
    local flowStartMilliseconds    = ebn.flowStartMilliseconds
    local flowEndMilliseconds      = ebn.flowEndMilliseconds
    local protocolIdentifier       = ebn.protocolIdentifier
    local ipClassOfService         = ebn.ipClassOfService
    local tcpControlBits           = ebn.tcpControlBits
    local icmpTypeCodeIPv4         = ebn.icmpTypeCodeIPv4
    local sourceTransportPort      = ebn.sourceTransportPort
    local sourceIPv4Address        = ebn.sourceIPv4Address
    local destinationTransportPort = ebn.destinationTransportPort
    local destinationIPv4Address   = ebn.destinationIPv4Address
    local bgpSourceAsNumber        = ebn.bgpSourceAsNumber
    local bgpDestinationAsNumber   = ebn.bgpDestinationAsNumber
    local flowEndReason            = ebn.flowEndReason

    local metric_bps = metric.bps
    local metric_pps = metric.pps
    local metric_fps = metric.fps

    local known_subnets = _M.config.integer_subnets

    local bucket = {}
    local last_bucket_time = 0

    local aggregate_stat = util.aggregate_stat

    local packets, bits, flows = 0,0,0

    while 1 == 1 do
        local now = math_ceil(fiber_time())
        local bucket_time = now - now % bucket_length

        -- Reset bucket if we're switching to a new one
        if bucket_time ~= last_bucket_time then
            if not aggregate_channel:put({last_bucket_time,bucket},_M.config.fiber_channel_timeout) then
                lp.dequeue('Error submitting bucket data to fiber channel, data lost!',5)
            end
            -- Reset bucket for directions
            bucket = { {}, {}, {} }
            log.info('Bucket reset with ' .. packets .. ' packets, ' .. bits  / 1024 / 1024 .. ' Mbits and ' .. flows .. ' flows at ' .. bucket_time)
            last_bucket_time = bucket_time
            packets, bits, flows = 0,0,0
        end

        local res = ipfix_channel:get()

        -- If we have a flow
        if res then
            local fields = res

            local flow_start,flow_end,flow_duration

            -- Normalise to milliseconds
            if fields[flowStartSeconds] and fields[flowEndSeconds] then
                flow_start = math_ceil(fields[flowStartSeconds].value * 1000)
                flow_end   = math_ceil(fields[flowEndSeconds].value * 1000)
            elseif fields[flowStartMilliseconds] and fields[flowEndMilliseconds] then
                flow_start = fields[flowStartMilliseconds].value
                flow_end   = fields[flowEndMilliseconds].value
            else
                lp.dequeue("Flow packet with no identifiable flow start / end - may be options template!",5)
            end

            -- if flow has valid start and end time, and also has delta changes for packets and octets
            if flow_start ~= nil and flow_end ~= nil and
                fields[packetDeltaCount] and fields[octetDeltaCount] then

                -- Extract deltas for metrics
                local deltaPackets = fields[packetDeltaCount].value
                local deltaBytes   = fields[octetDeltaCount].value

                local src_ip       = fields[sourceIPv4Address].value[1]
                local dst_ip       = fields[destinationIPv4Address].value[1]
                local src_ipnum    = ip.cidr_to_integer_range(src_ip)
                local dst_ipnum    = ip.cidr_to_integer_range(dst_ip)
                local src_as, dst_as
                if fields[bgpSourceAsNumber] then
                    src_as       = fields[bgpSourceAsNumber].value
                end
                if fields[bgpDestinationAsNumber] then
                    dst_as       = fields[bgpDestinationAsNumber].value
                end

                local src_subnet   = in_subnet(src_ip,known_subnets)
                local dst_subnet   = in_subnet(dst_ip,known_subnets)

                -- Ports can be unset if protocol has no concept of ports (ICMP..)
                local src_port, dst_port = 0,0

                if fields[sourceTransportPort] then
                    src_port     = fields[sourceTransportPort].value
                end
                if fields[destinationTransportPort] then
                    dst_port     = fields[destinationTransportPort].value
                end

                local protocol     = fields[protocolIdentifier].value
                local tos          = fields[ipClassOfService].value
                local status       = fields[flowEndReason].value

                local subnet, flow_dir, ip, flags, icmp_typecode

                if dst_subnet ~= nil then
                    flow_dir = direction.inbound
                    subnet   = dst_subnet
                    ip       = dst_ip
                elseif src_subnet ~= nil then
                    flow_dir = direction.outbound
                    subnet   = src_subnet
                    ip       = src_ip
                else
                    if src_as == 0 then
                        flow_dir = direction.outbound
                        subnet   = src_subnet
                        ip       = src_ip
                    elseif dst_as == 0 then
                        flow_dir = direction.inbound
                        subnet   = dst_subnet
                        ip       = dst_ip
                    else
                        log.error('Could not calculate flow direction for ' .. src_ip .. ' -> ' .. dst_ip .. ', ignoring...')
                    end
                end

                if flow_dir then
                    -- If this is a TCP flow, identify flags
                    if protocol == proto.TCP then
                        flags = decode_tcp_flags(fields[tcpControlBits].value)
                    end

                    -- If this is an ICMP flow, identify type and code
                    if protocol == proto.ICMP then
                        icmp_typecode = decode_icmp_type(fields[icmpTypeCodeIPv4])
                    end

                    local existing_flow = flow2table(spc_flows:get({
                        flow_start,
                        src_ip,
                        src_port,
                        dst_ip,
                        dst_port,
                        protocol,
                        tos,
                    }))

                    if existing_flow ~= nil then
                        flow_duration = (flow_end - existing_flow.end_ts) / 1000
                    else
                        -- Flow duration in seconds
                        flow_duration = (flow_end - flow_start) / 1000
                    end


                    -- If flow is active and longer than active_timeout, this is active_timeout worth of observations
                    if (status == flow_status.active_timeout and flow_duration > active_timeout) then
                        flow_duration = active_timeout 

                    -- Otherwise if flow is inactive and longer than idle_timeout, this is idle_timeout worth of observations
                    elseif (status ~= flow_status.active_timeout and flow_duration > idle_timeout) then
                        flow_duration = idle_timeout 
                    end

                    -- Make sure flow duration is never zero
                    -- Flows can be 0 length if they are a single UDP packet
                    -- In this case, just take the values as-is.
                    if flow_duration < 1 then
                        flow_duration = 1
                        observed_pps = deltaPackets / bucket_length
                        observed_bps = (deltaBytes * 8) / bucket_length
                    else
                        observed_pps = (deltaPackets * (bucket_length / flow_duration)) / bucket_length
                        observed_bps = ((deltaBytes * 8) * (bucket_length / flow_duration)) / bucket_length
                    end

                    observed_fps = 1

                    packets = packets + observed_pps
                    bits    = bits + observed_bps
                    flows   = flows + observed_fps

                    --if observed_bps > (2*1024*1024) then
                    --    log.info(tbl_concat({
                    --        flow_start,
                    --        flow_end,
                    --        proto_name(protocol),
                    --        flow_status_name(status), 
                    --        src_ip .. ':' .. src_port .. ' -> ' .. dst_ip .. ':' .. dst_port,
                    --        direction_name(flow_dir),
                    --        flow_duration,
                    --        'seconds',
                    --        observed_pps,
                    --        'pps',
                    --        observed_bps / 1024 / 1024,
                    --        'Mbps'
                    --    },' '))
                    --end

                    -- We cheat and just put flows into 'now' slot
                    local bucket_dir = bucket[flow_dir]

                    -- Global PPS / BPS / FPS
                    aggregate_stat(bucket_dir,'global',{observed_bps,observed_pps,observed_fps})

                    -- Global Protocol PPS / BPS / FPS
                    local proto_name = proto_name(protocol)
                    if proto_name then
                        aggregate_stat(bucket_dir,'protocol',proto_name,{observed_bps,observed_pps,observed_fps})
                    end

                    -- Subnet PPS / BPS / FPS
                    if subnet then
                        aggregate_stat(bucket_dir,'subnet',subnet,{observed_bps,observed_pps,observed_fps})
                        if proto_name then
                            aggregate_stat(bucket_dir,'protocol_subnet_' .. subnet,proto_name,{observed_bps,observed_pps,observed_fps})
                        end
                    end

                    -- IP PPS / BPS / FPS
                    if ip then
                        aggregate_stat(bucket_dir,'ip',ip,{observed_bps,observed_pps,observed_fps})
                        if proto_name then
                            aggregate_stat(bucket_dir,'protocol_ip_' .. ip,proto_name,{observed_bps,observed_pps,observed_fps})
                        end
                    end

                    -- Global Port PPS / BPS / FPS
                    if config.int_ports[src_port] then
                        aggregate_stat(bucket_dir,'port',src_port,{observed_bps,observed_pps,observed_fps})
                    elseif config.int_ports[dst_port] then
                        aggregate_stat(bucket_dir,'port',dst_port,{observed_bps,observed_pps,observed_fps})
                    end

                    -- Global / Subnet / IP TCP Flags PPS / BPS / FPS
                    if protocol == proto.TCP then
                        for _, flag in ipairs(flags) do
                            if flag[1] then
                                aggregate_stat(bucket_dir,'tcp_flag',flag[1],{observed_bps,observed_pps,observed_fps})
                                if subnet then
                                    aggregate_stat(bucket_dir,'tcp_flag_subnet_' .. subnet,flag[1],{observed_bps,observed_pps,observed_fps})
                                end
                                if ip then
                                    aggregate_stat(bucket_dir,'tcp_flag_ip_' .. ip,flag[1],{observed_bps,observed_pps,observed_fps})
                                end
                            end
                        end
                    end

                    -- ICMP Type/Code PPS / BPS / FPS
                    if protocol == proto.ICMP then
                        if icmp_typecode[1] then
                            aggregate_stat(bucket_dir,'icmp_typecode',icmp_typecode[1],{observed_bps,observed_pps,observed_fps})
                            if subnet then
                                aggregate_stat(bucket_dir,'icmp_typecode_subnet_' .. subnet,icmp_typecode[1],{observed_bps,observed_pps,observed_fps})
                            end
                            if ip then
                                aggregate_stat(bucket_dir,'icmp_typecode_ip_' .. ip,icmp_typecode[1],{observed_bps,observed_pps,observed_fps})
                            end
                        end
                    end

                    -- Store flow for use if an alert is triggered
                    -- {{{Start Timestamp}, {End Timestamp}}, Src IP, Src Port, Dst Ip, Dst Port, Proto, Tos}, Subnet, IP

                    spc_flows:replace({
                        flow_start,
                        flow_end,
                        src_ip,
                        src_port,
                        dst_ip,
                        dst_port,
                        protocol,
                        tos,
                        subnet or '',
                        ip or '',
                        flow_dir or direction.unknown,
                    })
                end
            end
        else
            fiber.sleep(0.1)
        end
    end
end

_M.start = function(ipfix_channel,aggregate_channel)
    return fiber.create(ipfix_aggregator,ipfix_channel,aggregate_channel)
end

return _M
