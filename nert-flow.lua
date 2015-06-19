#!/usr/bin/env tarantool
local os          = require("os")
local binutil     = require("binutil")
local ipfix       = require("ipfix")
local ip          = require("ip")
local math_ceil   = math.ceil
local math_floor  = math.floor
local lp          = require("logprint")

local expirationd = require("expirationd")
local bit_band    = bit.band

local http        = require("http.server")
local fiber       = require("fiber")
local yaml        = require("yaml")
local log         = require("log")
local log_error   = log.error
local log_info   = log.info
local log_debug   = log.debug
local json        = require("json")
local json_encode = json.encode

local socket      = require("socket")


function rPrint(s, l, i) -- recursive Print (structure, limit, indent)
    l = (l) or 500; i = i or "";        -- default item limit, indent string
    if (l<1) then print "ERROR: Item limit reached."; return l-1 end;
    local ts = type(s);
    if (ts ~= "table") then print (i,ts,s); return l-1 end
    print (i,ts);           -- print "table"
    for k,v in pairs(s) do  -- print "[KEY] VALUE"
        l = rPrint(v, l, i.."\t["..tostring(k).."]");
        if (l < 0) then break end
    end
    return l
end

local config = {}
local elements = { by_name = {}, by_id = {} }


-- Define constants
local tcp_flags = {
    FIN = 1,
    SYN = 2,
    RST = 4,
    ACK = 8,
    URG = 32,
    ECE = 64,
    CWR = 128,
    NS  = 256,
}

local proto = {
    ICMP = 1,
    TCP  = 6,
    UDP  = 17,
    GRE  = 47,
    ESP  = 50,
    AH   = 51,
    SCTP = 132,
}

local direction = {
    inbound  = 1,
    outbound = 2,
    unknown  = 3,
}

local metrics = {
    bps = 1,
    pps = 2,
    fps = 3,
}

-- Define reverse mappings
local tcp_flags_reverse = {}
local proto_reverse = {}
local direction_reverse = {}
local metrics_reverse = {}


local tcp_flags_name = function(tcp_flags_num)
    return tcp_flags_reverse[tcp_flags_num] or 'unknown'
end

local proto_name = function(proto_num)
    return proto_reverse[proto_num] or 'Other'
end

local direction_name = function(direction_num) 
    return direction_reverse[direction_num] or 'unknown'
end

local metrics_name = function(metrics_num) 
    return metrics_reverse[metrics_num] or 'unknown'
end

local load_config = function()
    local f,err = io.open("./nert-flow.yaml", "r")
    
    if not f then
        print("Error: " .. err)
        os.exit(1)
    end

    config = yaml.decode(f:read("*all"))
    f:close()

    local f,err = io.open("./iana_dict.yaml", "r")
    constants = yaml.decode(f:read("*all"))
    elements.by_id = constants.elements
    f:close()

    for id, fields in pairs(elements.by_id) do
        elements.by_name[fields.name] = id
    end

    config.fiber_channel_timeout   = config.fiber_channel_timeout or 1
    config.fiber_channel_capacity  = config.fiber_channel_capacity or 1024
    config.fiber_channel_full_perc = config.fiber_channel_full_perc or 0.85
    config.ipfix_tpl_save_interval = config.ipfix_tpl_save_interval or 300
    config.active_timeout          = config.active_timeout or 60
    config.idle_timeout            = config.idle_timeout or 60
    config.bucket_length           = config.bucket_length or 10
    config.bucket_count            = config.bucket_count or 360
    config.ports                   = config.ports or { 2055 }
    config.max_history             = config.bucket_length * config.bucket_count
    
    local thresholds = config.thresholds
    for tcp_flags_name, tcp_flags_num in pairs(tcp_flags) do
        tcp_flags_reverse[tcp_flags_num] = tcp_flags_name
    end
    for proto_name, proto_num in pairs(proto) do
        proto_reverse[proto_num] = proto_name
    end
    for direction_name, direction_num in pairs(direction) do
        direction_reverse[direction_num] = direction_name
    end

    local interesting_ports = config.interesting_ports
    config.int_ports = {}

    for _,port in ipairs(config.interesting_ports) do
        config.int_ports[port] = true
    end

    config.integer_subnets = {}
    for _,subnet in ipairs(config.subnets) do
        local sub_lo, sub_high = ip.cidr_to_integer_range(subnet)
        table.insert(config.integer_subnets,{sub_lo,sub_high})
    end
end

local load_ipfix = function()
    ipfix.configure(config,elements.by_id)
    ipfix.load_templates(config.ipfix_tpl_cache_file)
end

local bootstrap_db = function()
    box.cfg({
        listen = config.db_port or 3301,
        work_dir = config.work_dir or "./data",
        snapshot_period = 300,
        snapshot_count  = 5,
    })
end

local setup_user = function()
    if not box.schema.user.exists('guest') then
        box.schema.user.create('guest', {password = box.info.server.uuid})
        box.schema.user.grant('guest','read,write,execute','universe')
    end
end

local in_subnet = function(subnet)
    local subnets = config.integer_subnets
    for i=1, #subnets do
        local sub_low, sub_high = unpack(subnets[i])

        local ip_low, ip_high = ip.cidr_to_integer_range(subnet.. '/32')

        if ip_low > sub_low and ip_high < sub_high then
            return ip.integer_range_to_cidr(sub_low,sub_high)
        end
    end
    return nil
end

local bucket_member_invalid = function(args,tuple)
    local now = math_ceil(fiber.time())
    
    local older = tuple[1] < (now - args.max_history)
    if older then
        log.info(tuple[1] .. ' < ' .. (now - args.max_history) .. ' (now is ' .. now .. ')')
    end
    return older
end

local bucket_member_delete = function(space_id,args,tuple)
    log.info('Deleting row from space ' .. space_id .. ' with timestamp ' .. tuple[1])
    box.space[space_id]:delete(tuple)
end

local setup_db = function()
    -- FLOWS: {{{Start Timestamp}, {End Timestamp}}, Src IP, Src Port, Dst Ip, Dst Port, Proto, Tos}, Subnet, IP
    box.schema.space.create('flows',{field_count=10,if_not_exists = true})
    box.space.flows:create_index('primary',{unique = true, type = 'HASH', parts = {1, 'NUM', 3, 'STR', 4, 'NUM', 5, 'STR', 6, 'NUM', 7, 'NUM', 8, 'NUM'}, if_not_exists = true})
    box.space.flows:create_index('by_end_ts',{unique = false, parts = {2, 'NUM', 3, 'STR', 4, 'NUM', 5, 'STR', 6, 'NUM', 7, 'NUM', 8, 'NUM'}, if_not_exists = true})
    box.space.flows:create_index('by_hash',{unique = false, parts = {3, 'STR', 4, 'NUM', 5, 'STR', 6, 'NUM', 7, 'NUM', 8, 'NUM'}, if_not_exists = true})
    box.space.flows:create_index('by_dst_ip',{unique = false, parts = {5, 'STR'}, if_not_exists = true})
    box.space.flows:create_index('by_src_ip',{unique = false, parts = {3, 'STR'}, if_not_exists = true})
    box.space.flows:create_index('by_dst_port',{unique = false, parts = {6, 'NUM'}, if_not_exists = true})
    box.space.flows:create_index('by_src_port',{unique = false, parts = {4, 'NUM'}, if_not_exists = true})
    box.space.flows:truncate()
    expirationd.run_task('expire_flows', box.space.flows.id, bucket_member_invalid, bucket_member_delete, {max_history = config.max_history}, 50, 3600)

    -- {Timestamp}, Data 
    box.schema.space.create('buckets',{field_count=2,if_not_exists = true})
    box.space.buckets:create_index('primary',{unique = true, type = 'HASH', parts = {1, 'NUM'}, if_not_exists = true})
    expirationd.run_task('expire_buckets', box.space.buckets.id, bucket_member_invalid, bucket_member_delete, {max_history = config.max_history}, 50, 3600)
end


local flow2table = function(flow)
    if flow == nil then
        return nil
    end

    return {
        start_ts    = flow[1],
        end_ts      = flow[2],
        src_ip      = flow[3],
        src_port    = flow[4],
        dst_ip      = flow[5],
        dst_port    = flow[6],
        proto       = flow[7],
        tos         = flow[8],
        subnet      = flow[9],
        ip          = flow[10],
    }
end

local flow2tuple = function(flow)
    if flow == nil then
        return nil
    end

    return {
        flow.start_ts,
        flow.end_ts,
        flow.src_ip,
        flow.src_port,
        flow.dst_ip,
        flow.dst_port,
        flow.proto,
        flow.tos,
        flow.subnet,
        flow.ip,
    }
end

local ipfix_listener = function(port,channel)

    -- Bind to configured ports
    local sock = socket('AF_INET','SOCK_DGRAM', 'udp')
    sock:bind("0.0.0.0",port)

    -- Set fiber listener name
    local self = fiber.self()
    self:name("ipfix/listener-port-" .. port)

    while 1 == 1 do
        -- Wait until socket has data to read
        sock:readable()
        local packet, sa = sock:recvfrom()
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
                                    if channel_count > (config.fiber_channel_capacity * config.fiber_channel_full_perc) then
                                        lp.dequeue("Fiber channel is almost full! Please check your fiber_channel_capacity setting",5)
                                    end
                                    local flow = new_flows[i]
                                    if not channel:put(flow,config.fiber_channel_timeout) then
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

local listener_ports = {}

local start_ipfix_listener = function(port,channel)
    if not listener_ports[port] then
        print("Starting listener on port " .. port)
        fiber.create(ipfix_listener,port,channel)
        listener_ports[port] = true
    end
end


local ipfix_aggregator = function(ipfix_channel,aggregate_channel)
    -- Set fiber listener name
    local self = fiber.self()
    self:name("ipfix/aggregator")

    
    local decode_icmp_type = function(type_raw)
        return bit_band(256,type_raw)
    end

    local decode_tcp_flags = function(flags_raw)
        local flags = {} 

        for value, name in ipairs(tcp_flags) do
            if bit_band(value,flags_raw == value) then
                flags[value] = true
            end
        end

        return flags
    end

    local status_active     = 1

    local spc_flows                = box.space.flows

    -- We normalise flows to seconds. Bucket length is in seconds
    local bucket_length            = config.bucket_length
    local bucket_count             = config.bucket_count
    local active_timeout           = config.active_timeout
    local idle_timeout             = config.idle_timeout

    local ebn = elements.by_name
    local packetDeltaCount         = ebn.packetDeltaCount
    local octetDeltaCount          = ebn.octetDeltaCount
    local flowStartSeconds         = ebn.flowStartSeconds
    local flowEndSeconds           = ebn.flowEndSeconds
    local flowStartMilliseconds    = ebn.flowStartMilliseconds
    local flowEndMilliseconds      = ebn.flowEndMilliseconds
    local protocolIdentifier       = ebn.protocolIdentifier
    local ipClassOfService         = ebn.ipClassOfService
    local tcpControlBits           = ebn.tcpControlBits
    local sourceTransportPort      = ebn.sourceTransportPort
    local sourceIPv4Address        = ebn.sourceIPv4Address
    local destinationTransportPort = ebn.destinationTransportPort
    local destinationIPv4Address   = ebn.destinationIPv4Address
    local bgpSourceAsNumber        = ebn.bgpSourceAsNumber
    local bgpDestinationAsNumber   = ebn.bgpDestinationAsNumber
    local flowEndReason            = ebn.flowEndReason

    local metric_bps = metrics.fps
    local metric_pps = metrics.pps
    local metric_fps = metrics.fps

    local bucket = {}
    local last_bucket_time = 0

    local aggregate_stat = function(store,typ,stat,values)
        if not store[typ] then
            store[typ] = {}
        end
        if not store[typ][stat] then
            store[typ][stat] = {}
        end


        -- double exp_power = -speed_calc_period / average_calculation_amount_for_subnets;
        -- double exp_value = exp(exp_power);
        -- 
        -- map_element* current_average_speed_element = &PerSubnetAverageSpeedMap[current_subnet];
        -- 
        -- current_average_speed_element->in_bytes = uint64_t(new_speed_element.in_bytes +
        --     exp_value * ((double)current_average_speed_element->in_bytes - (double)new_speed_element.in_bytes));


        local exp_power = -
        for key, value in ipairs(values) do
            if store[typ][stat][key] == nil then
                store[typ][stat][key] = value
            else
                store[typ][stat][key] = store[typ][stat][key] + value
            end
        end
    end

    while 1 == 1 do
        local now = fiber.time()
        local bucket_time = now - now % bucket_length

        -- Reset bucket if we're switching to a new one
        if bucket_time ~= last_bucket_time then
            aggregate_channel:put({last_bucket_time,bucket})
            -- Reset bucket for directions
            bucket = { {}, {}, {} }
            log.info('Bucket reset, bucket time is now ' .. bucket_time)
            last_bucket_time = bucket_time
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
                lp.dequeue("Flow packet with no identifiable flow start / end",5)
            end

            -- if flow has valid start and end time
            if flow_start ~= nil and flow_end ~= nil then

                -- Extract deltas for metrics
                local deltaPackets = fields[packetDeltaCount].value
                local deltaBytes   = fields[octetDeltaCount].value

                local src_ip       = fields[sourceIPv4Address].value[1]
                local dst_ip       = fields[destinationIPv4Address].value[1]
                local src_ipnum    = ip.cidr_to_integer_range(src_ip)
                local dst_ipnum    = ip.cidr_to_integer_range(dst_ip)
                local src_as       = fields[bgpSourceAsNumber].value
                local dst_as       = fields[bgpDestinationAsNumber].value
                local src_subnet   = in_subnet(src_ip)
                local dst_subnet   = in_subnet(dst_ip)
                local src_port     = fields[sourceTransportPort].value
                local dst_port     = fields[destinationTransportPort].value
                local protocol     = fields[protocolIdentifier].value
                local tos          = fields[ipClassOfService].value
                local flow_status  = fields[flowEndReason].value

                local subnet, flow_dir, ip,tcp_flags

                if src_as == 0 then
                    flow_dir = direction.outbound
                    subnet = src_subnet
                    ip = src_ip
                elseif dst_as == 0 then
                    flow_dir = direction.inbound
                    subnet = dst_subnet
                    ip = dst_ip
                else
                    -- Fall back to identifying by Subnet
                    if src_subnet ~= nil then
                        flow_dir = direction.outbound
                        subnet = src_subnet
                        ip = src_ip
                    elseif dst_subnet ~= nil then
                        flow_dir = direction.inbound
                        subnet = dst_subnet
                        ip = dst_ip
                    else
                        log.error('Could not calculate flow direction for ' .. src_ip .. ' -> ' .. dst_ip .. ', ignoring...')
                    end
                end

                -- Store flow for use if flow triggers alert
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
                })

                -- If this is a TCP flow, identify flags
                if protocol == proto.TCP then
                    tcp_flags = decode_tcp_flags(fields[tcpControlBits].value)
                end

                -- Flow duration in seconds
                flow_duration = (flow_end - flow_start) / 1000

                -- If flow is active and longer than active_timeout, this is active_timeout worth of observations
                if (flow_status == flow_active and flow_duration > active_timeout) then
                    flow_duration = active_timeout 

                -- Otherwise if flow is inactive and longer than idle_timeout, this is idle_timeout worth of observations
                elseif (flow_status ~= flow_active and flow_duration > idle_timeout) then
                    flow_duration = idle_timeout 
                end

                -- Make sure flow duration is never zero
                if flow_duration == 0 then
                    flow_duration = 0.001 -- Shortest possible flow duration is 1ms
                end

                -- Our bucket is x seconds long
                -- Our flow can be longer or shorter than that
                
                -- Calculate observed average speeds
                observed_pps = deltaPackets / flow_duration
                observed_bps = deltaBytes / flow_duration
                observed_fps = 1 / flow_duration

                log.info(
                -- We cheat and just put flows into 'now' slot
                local now = fiber.time()

                local bucket_dir = bucket[flow_dir]

                -- Global PPS / BPS / FPS
                aggregate_stat(bucket_dir,'global','',{observed_bps,observed_pps,observed_fps})

                -- Protocol PPS / BPS / FPS
                local proto_name = proto_name(protocol)
                aggregate_stat(bucket_dir,'protocol',proto_name,{observed_bps,observed_pps,observed_fps})

                -- Subnet PPS / BPS / FPS
                if subnet then
                    aggregate_stat(bucket_dir,'subnet',subnet,{observed_bps,observed_pps,observed_fps})
                end

                -- IP PPS / BPS / FPS
                if ip then
                    aggregate_stat(bucket_dir,'ip',ip,{observed_bps,observed_pps,observed_fps})
                end

                -- Port PPS / BPS / FPS
                if config.int_ports[src_port] then
                    aggregate_stat(bucket_dir,'port',src_port,{observed_bps,observed_pps,observed_fps})
                elseif config.int_ports[dst_port] then
                    aggregate_stat(bucket_dir,'port',dst_port,{observed_bps,observed_pps,observed_fps})
                end

                -- TCP Flags PPS / BPS / FPS
                if protocol == proto.TCP then
                    for num,flag in ipairs(tcp_flags_reverse) do
                        aggregate_stat(bucket_dir,'tcp_flag',flag,{observed_bps,observed_pps,observed_fps})
                    end
                end
            end
        else
            fiber.sleep(0.1)
        end
    end
end

local bucket_monitor = function(aggregate_channel,graphite_channel)
    local bucket_length  = config.bucket_length
    local active_timeout = config.active_timeout
    local idle_timeout   = config.idle_timeout

    local spc_buckets = box.space.buckets
    while 1 == 1 do
        local bucket_data = aggregate_channel:get() 
        local bucket_ts,bucket_stats = bucket_data[1], bucket_data[2]

        local graphite_output = {}
        
        if bucket_stats ~= nil then
            --spc_buckets:update({bucket_ts,bucket_stats})
            -- For each direction
            for direction, stat_types in ipairs(bucket_stats) do
                -- For each type
                for stat_type, stats in pairs(stat_types) do
                    for stat, values in pairs(stats) do
                        local sanitized_stat_name = tostring(stat):lower():gsub('/','_'):gsub('%.','_')

                        local graphite_name = table.concat({
                            'flow',
                            stat_type:lower(),
                            sanitized_stat_name,
                            direction_name(direction),
                        },'.'):gsub('%.%.','.')

                        
                        graphite_channel:put({graphite_name .. '.bps',values[1],bucket_ts})
                        graphite_channel:put({graphite_name .. '.pps',values[2],bucket_ts})
                        graphite_channel:put({graphite_name .. '.fps',values[3],bucket_ts})
                    end
                end
            end
        end

        fiber.sleep(0.1)
    end
end

local graphite_submitter = function(graphite_channel)
    local pending = 0
    local output = ''
    local conn_info = socket.getaddrinfo(config.graphite_host,'2010')
    local graphite_host = conn_info[1].host
    local graphite_port = conn_info[1].port

    if not graphite_host or not graphite_port then
        log.info('Disabling graphite submission, no host or port configured!')
        return
    end

    local graphite = socket('AF_INET', 'SOCK_DGRAM', 'udp')

    while 1 == 1 do
        local to_submit = graphite_channel:get()
        if to_submit ~= nil then
            pending = pending + 1
            output = output .. table.concat(to_submit,' ') .. "\n"
        end

        if pending >= 5 or to_submit == nil then
            log.info(output)
            local sent = graphite:sendto(graphite_host,graphite_port,output)
            if not sent then
                log.error('Metric output to Graphite at ' .. graphite_host .. ':' .. graphite_port .. ' failed! - ' .. graphite:error())
            end
            pending = 0
            output  = ''
            fiber.sleep(0.01)
        end
    end
    graphite:close()
end

local ipfix_background_saver = function()
    local self = fiber.self()
    self:name("ipfix/background-saver")
    while 1 == 1 do
        -- Sleep for save_interval seconds between each save
        fiber.sleep(config.ipfix_tpl_save_interval)
        print("Saving IPFIX templates...")
        ipfix.save_templates(config.ipfix_tpl_cache_file)
    end
end

local start_fibers = function()
    -- Start listener for each unique listening port (we *can* have multiple sources per port)
    local ipfix_channel     = fiber.channel(config.fiber_channel_capacity or 1024)
    local aggregate_channel = fiber.channel(1024)
    local graphite_channel  = fiber.channel(8192)

    fiber.create(ipfix_background_saver)

    -- Write to ipfix_channel
    for _, port in ipairs(config.ports) do
        start_ipfix_listener(port,ipfix_channel)
    end

    -- Read from ipfix_channel, write to aggregate_channel
    fiber.create(ipfix_aggregator,ipfix_channel,aggregate_channel) 

    -- Read from aggregate_channel, write to graphite_channel
    fiber.create(bucket_monitor,aggregate_channel,graphite_channel)

    -- Read from graphite_channel
    fiber.create(graphite_submitter,graphite_channel)
end

local start_http_server = function()
    local bucket_length = config.bucket_length

    print("Start HTTP Server on " .. config.http_host .. ":" .. config.http_port )
    server = http.new(config.http_host, config.http_port, {app_dir = '..', cache_static = false})

    server:route({ path = '/' }, function(self)
        return self:redirect_to('/index.html')
    end)

    server:route({ path = '/config' }, function(self)
        local response = {
            config = config,
            time = math_ceil(fiber.time()),
        }
        return self:render{ json = response }
    end)

    server:route({ path = '/stats' }, function(self)
       local response = {
           flows        = box.space.flows.index.primary:count(),
           tarantool = {
               slab = box.slab.info(),
               stat = box.stat(),
           },
       }
       return self:render{ json = { stats = response, time = math_ceil(fiber.time())}}
    end)

    server:route({ path = '/fibers' }, function(self)
        local response = fiber.info()
        return self:render{ json = response }
    end)
    
    server:route({ path = '/buckets/:stat', method='GET' }, function(self)
        local stat = self:stash('stat')

        return self:render{ json = { buckets = buckets } }
    end)

    server:route({ path = '/flows/', method='GET' }, function(self)
        local now = fiber.time()
        local bucket_ts = math_ceil(now - now % bucket_length) - 60
        local out = { {}, {}, {} }
        for dir, times in ipairs(buckets) do
            local bucket = times[bucket_ts]

            if bucket then
                for name, items in pairs(bucket_indexes) do
                    if out[dir][name] == nil then
                        out[dir][name] = {}
                    end

                    if type(items) == 'table' then
                        for item, id in pairs(items) do
                            out[dir][name][item] = bucket[id]
                        end
                    else
                        out[dir][name] = bucket[items]
                    end
                        
                end
            end
        end

        return self:render{ json = { bucket = bucket_ts, results = out } }
    end)

    -- SOURCES: {Listen IP, Listen Port}, Name, Group, Options, Active
    server:route({ path = '/sources/', method='GET' }, function(self)
        local results = {}
        for _, source in box.space.sources:pairs{} do
            table.insert(results,source2table(source))
        end
        
        return self:render{ json = results }
    end)

    server:route({ path = '/sources/', method='ANY' }, function(self)
        local args = self:json()

        if self.method == 'DELETE' then
            local result,err = box.space.sources.index.primary:delete({args.source_ip,args.listen_port})
            local response = self:render{ json = {} }
            if err ~= nil then
                response.status = 404
                response = err
            else 
                response.status = 204
            end
        elseif self.method == 'PUT' then

            if args.active == nil then
                args.active = true
            end

            local result,err = box.space.sources:replace(source2tuple(args))
            local response = self:render{ json = result or {} }
            if err ~= nil then
                response.status = 400
                response = err
            else 
                start_ipfix_listener(args.listen_port)
                response.headers['Location'] = '/source/' .. args.name
                response.status = 201
            end
        else
            local response = self:render{ status = 400 }
        end
        return response
    end)
    
    server:start()
end

load_config()
bootstrap_db()
setup_user()
setup_db()
load_ipfix()
start_fibers()
start_http_server()

