#!/usr/bin/env tarantool
local dirname     = require("fio").dirname

-- Set location of executed file into package.path
local root    = dirname(arg[0])

package.path = package.path .. ";" .. root .. "/?.lua;" .. root .. '/lib/?.lua'

local os          = require("os")
local binutil     = require("binutil")
local ipfix       = require("ipfix")
local ip          = require("ip")
local math_ceil   = math.ceil
local math_floor  = math.floor
local lp          = require("logprint")

local digest      = require("digest")

local expirationd = require("expirationd")
local bit_band    = bit.band
local bit_rshift  = bit.rshift

local tbl_concat  = table.concat
local tbl_insert  = table.insert
local http        = require("http.server")
local fiber       = require("fiber")
local yaml        = require("yaml")
local log         = require("log")
local log_error   = log.error
local log_info    = log.info
local log_debug   = log.debug
local json        = require("json")
local json_encode = json.encode

local events      = require("events")

local socket      = require("socket")

ProFi = require 'ProFi'
ProFi:setGetTimeMethod(fiber.time)

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
    ICMP  = 1,
    IGMP  = 2,
    IPV4  = 4,
    TCP   = 6,
    UDP   = 17,
    GRE   = 47,
    ESP   = 50,
    AH    = 51,
    EIGRP = 88,
    OSPF  = 89,
    ISIS  = 124,
    SCTP  = 132,
}

local direction = {
    inbound  = 1,
    outbound = 2,
    unknown  = 3,
}

local metric = {
    bps = 1,
    pps = 2,
    fps = 3,
}

local metric_totals = {
    bps = 4,
    pps = 5,
    fps = 6,
}

local flow_status = {
    idle_timeout   = 1,
    active_timeout = 2,
    ended          = 3,
    force_ended    = 4,
    lor_ended      = 5,
}

local icmp_types = {
    [0]  = 'echo_reply',
    [3]  = {
            'net_unreachable',
            'host_unreachable',
            'protocol_unreachable',
            'port_unreachable',
            'frag_needed_df_set',
            'src_route_failed',
            'dst_net_unknown',
            'dst_host_unknown',
            'src_host_isolated',
            'dst_net_admin_prohibited',
            'dst_host_admin_prohibited',
            'dst_net_unreachable_tos',
            'dst_host_unreachable_tos',
            'admin_prohibited',
            'host_precedence_violation',
            'precedence_cutoff_in_effect',
    },
    [4]  = 'src_quench',
    [5]  = {
            'redirect_net',
            'redirect_host',
            'redirect_tos_net',
            'redirect_tos_host',
    },
    [6]  = 'alt_addr_host',
    [8]  = 'echo',
    [9]  = 'router_advertisement',
    [10] = 'router_selection',
    [11] = {
            'ttl_exceeded',
            'frag_reassembly_ttl_exceeded',
    },
    [12] = { 
            'ptr_indicates_err',
            'missing_reqd_option',
            'bad_length',
    },
    [13] = 'timestamp',
    [14] = 'timestamp_reply',
    [15] = 'info_request',
    [16] = 'info_reply',
    [17] = 'addr_mask_request',
    [18] = 'addr_mask_reply',
    [30] = 'traceroute',
    [31] = 'dgram_conversion_err',
    [32] = 'mobile_host_redirect',
    [33] = 'ipv6_where_are_you',
    [34] = 'ipv6_i_am_here',
    [35] = 'mobile_reg_request',
    [36] = 'mobile_reg_reply',
    [39] = 'skip',
    [40] = 'photuris'
}

-- Define reverse mappings
local tcp_flags_reverse   = {}
local tcp_flags_iter      = {}
local proto_reverse       = {}
local proto_iter          = {}
local direction_reverse   = {}
local direction_iter      = {}
local flow_status_reverse = {}
local flow_status_iter    = {}
local metric_reverse      = {}
local metric_totals_reverse      = {}
local ip_addr             = {}
local ip_addr_reverse     = {}
local ip_addr_iter        = {}


local tcp_flags_name = function(tcp_flags_num)
    if not tcp_flags_reverse[tcp_flags_num] then
        log.error('Unidentified TCP flag: ' .. tcp_flags_num)
    end
    return tcp_flags_reverse[tcp_flags_num] or 'unknown'
end

local proto_name = function(proto_num)
    if not proto_reverse[proto_num] then
        log.error('Unidentified protocol number: ' .. proto_num)
    end
    return proto_reverse[proto_num] or 'other'
end

local direction_name = function(direction_num) 
    return direction_reverse[direction_num] or 'unknown'
end

local flow_status_name = function(flow_status_num) 
    if not flow_status_reverse[flow_status_num] then
        log.error('Unidentified flow status: ' .. flow_status_num)
    end
    return flow_status_reverse[flow_status_num] or 'unknown'
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

    config.fiber_channel_timeout      = config.fiber_channel_timeout or 1
    config.fiber_channel_capacity     = config.fiber_channel_capacity or 1024
    config.fiber_channel_full_perc    = config.fiber_channel_full_perc or 0.85
    config.ipfix_tpl_save_interval    = config.ipfix_tpl_save_interval or 300
    config.active_timeout             = config.active_timeout or 60
    config.idle_timeout               = config.idle_timeout or 60
    config.bucket_length              = config.bucket_length or 10
    config.bucket_count               = config.bucket_count or 360
    config.ports                      = config.ports or { 2055 }
    config.max_history                = config.bucket_length * config.bucket_count
    config.alert_active_time          = config.alert_active_time or 30
    config.alert_expiry_time          = config.alert_expiry_time or 60
    config.average_calculation_period = config.average_calculation_period or (config.bucket_length * 3)
    config.thresholds                 = config.thresholds or {}
    config.attack_protocol_ratio      = config.attack_protocol_ratio or 0.9
    config.max_flow_packet_length     = config.max_flow_packet_length or 8192
    
    -- Create reverse lookup structures for 'constants'
    -- Also create iterable structures for 'constants' which 
    -- are not numerically in sequence (i.e. not 1,2,3 but 4,6,17 etc)
    -- This means we can use them with ipairs but have to unpack the table

    local thresholds = config.thresholds
    for tcp_flags_name, tcp_flags_num in pairs(tcp_flags) do
        tcp_flags_reverse[tcp_flags_num] = tcp_flags_name
        tbl_insert(tcp_flags_iter,{tcp_flags_name,tcp_flags_num})
    end
    for proto_name, proto_num in pairs(proto) do
        proto_reverse[proto_num] = proto_name
        tbl_insert(proto_iter,{proto_name,proto_num})
    end
    for direction_name, direction_num in pairs(direction) do
        direction_reverse[direction_num] = direction_name
        tbl_insert(direction_iter,{direction_name,direction_num})
    end
    for flow_status_name, flow_status_num in pairs(flow_status) do
        flow_status_reverse[flow_status_num] = flow_status_name
        tbl_insert(flow_status_iter,{flow_status_name,flow_status_num})
    end
    for metric_name, metric_num in pairs(metric) do
        metric_reverse[metric_num] = metric_name
    end
    for metric_totals_name, metric_totals_num in pairs(metric_totals) do
        metric_totals_reverse[metric_totals_num] = metric_totals_name
    end

    local interesting_ports = config.interesting_ports
    config.int_ports = {}

    for _,port in ipairs(config.interesting_ports) do
        config.int_ports[port] = true
    end

    config.integer_subnets = {}
    for _,subnet in ipairs(config.subnets) do
        local sub_lo, sub_high = ip.cidr_to_integer_range(subnet)
        -- For each subnet, generate list of IPs
        for i = sub_lo, sub_high do
            -- Get IP address without subnet mask
            local ip_address = ip.integer_range_to_cidr(i,false)
            tbl_insert(ip_addr_iter,{ip_address,i})
            ip_addr[ip_address]     = i
            ip_addr_reverse[i] = ip_address
        end
        tbl_insert(config.integer_subnets,{sub_lo,sub_high,subnet})
    end

    events.set_config(config)
end

local load_ipfix = function()
    ipfix.configure(config,elements.by_id)
    ipfix.load_templates(config.ipfix_tpl_cache_file)
end

local bootstrap_db = function()
    box.cfg({
        listen             = config.db_port or 3301,
        work_dir           = config.work_dir or "./data",
        snapshot_period    = 300,
        snapshot_count     = 5,
        slab_alloc_arena   = 2.0,
        slab_alloc_minimal = 64,
        slab_alloc_maximal = 786432,
        slab_alloc_factor  = 0.9,
        custom_proc_title  = 'NeRT Flow'
    })
end

local setup_user = function()
    if not box.schema.user.exists('guest') then
        box.schema.user.create('guest', {password = box.info.server.uuid})
        box.schema.user.grant('guest','read,write,execute','universe')
    end
end

local get_consistent = function(hash_fields,buckets)
    local base_hash = digest.crc32(tbl_concat(hash_fields) .. fiber.time())

    local selected_bucket = digest.guava(base_hash,#buckets)

    return buckets[selected_bucket]
end


local in_subnet = function(subnet)
    local subnets = config.integer_subnets
    for i=1, #subnets do
        local sub_low, sub_high, cidr = unpack(subnets[i])

        local ip_low, ip_high = ip.cidr_to_integer_range(subnet)

        if ip_low > sub_low and ip_high < sub_high then
            return cidr
        end
    end
    return nil
end

local pretty_duration = function(duration)
    local pretty_table = {}

    -- Durations are in seconds
    -- If duration is more than an hour
    if duration > 3600 then
        hours = math.floor(duration / 3600)
        duration = duration - hours * 3600
        tbl_insert(pretty_table,string.format('%dh',hours))
    end

    if duration > 60 then
        minutes = math.floor(duration / 60)
        duration = duration - minutes * 60
        tbl_insert(pretty_table,string.format('%dm',minutes))
    end
    if duration > 0 then
        tbl_insert(pretty_table,string.format('%ds',duration))
    end

    return tbl_concat(pretty_table,' ')
end

local pretty_value = function(value,typ)
    local unit, divider
    -- 1024
    if typ == metric.bps or typ == metric_totals.bps then
        local end_unit
        if typ == metric.bps then
            end_unit = 'bps'
        else
            end_unit = 'bytes'
        end
        if value > 1073741824 then
            unit    = 'G'..end_unit
            divider = 1073741824
        elseif value > 1048576 then
            unit    = 'M'..end_unit
            divider = 1048576
        elseif value > 1024 then
            unit    = 'K'..end_unit
            divider = 1024
        else
            unit    = end_unit
            divider = 1
        end
    -- 1000
    elseif typ == metric.pps or typ == metric.fps 
      or typ == metric_totals.pps or typ == metric_totals.fps then
        local end_unit
        if typ == metric.pps then
            end_unit = 'pps'
        elseif typ == metric.fps then
            end_unit = 'fps'
        elseif typ == metric_totals.pps then
            end_unit = 'packets'
        elseif typ == metric_totals.fps then
            end_unit = 'flows'
        end

        if value > 1000000000 then
            unit    = 'G'..end_unit
            divider = 1000000000
        elseif value > 1000000 then
            unit    = 'M'..end_unit
            divider = 1000000
        elseif value > 1000 then
            unit    = 'K'..end_unit
            divider = 1000
        else
            unit    = end_unit
            divider = 1
        end
    end
    return string.format('%.2f %s', value / divider, unit)
end

local uc_first = function(str)
    return (str:gsub("^%l", string.upper))
end

local dedup_keys = function(input,use_values)
    local output = {}
    for key, value in pairs(input) do
        if use_values then
            tbl_insert(output,tbl_concat({key,value},' '))
        else
            tbl_insert(output,key)
        end
    end
    return output
end

local alert2table = function(alert)
    if alert == nil then
        return nil
    end
    return {
        start_ts       = alert[1],
        direction      = alert[2],
        target_type    = alert[3],
        target         = alert[4],
        active         = alert[5] == 1,
        value          = alert[6],
        threshold      = alert[7],
        duration       = alert[8],
        notified_start = alert[9],
        notified_end   = alert[10],
        details        = alert[11],
        updated_ts     = alert[12],
    }
end

local alert2tuple = function(alert)
    if alert == nil then
        return nil
    end

    local active
    if alert.active then
        active = 1
    else
        active = 0
    end

    local notified_start
    if alert.notified_start then
        notified_start = 1
    else
        notified_start = 0
    end

    local notified_end
    if alert.notified_end then
        notified_end = 1
    else
        notified_end = 0
    end

    return {
        alert.start_ts,
        alert.direction,
        alert.target_type,
        alert.target,
        active,
        math_ceil(alert.value),
        math_ceil(alert.threshold),
        math_ceil(alert.duration),
        notified_start,
        notified_end,
        alert.details or {},
        math_ceil(alert.updated_ts),
    }
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
        direction   = flow[11],
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
        flow.direction,
    }
end

local bucket2table = function(bucket)
    if bucket == nil then
        return nil
    end
    return {
        ts   = bucket[1],
        data = bucket[2],
    }
end

local bucket2tuple = function(bucket)
    if bucket == nil then
        return nil
    end

    return {
        bucket.ts,
        bucket.data,
    }
end

local avg2table = function(avg)
    if avg == nil then
        return nil
    end
    return {
        stat_type   = avg[1],
        stat        = avg[2],
        direction   = avg[3],
        values      = avg[4],
        last_updated = avg[5],
    }
end

local avg2tuple = function(avg)
    if avg == nil then
        return nil
    end

    return {
        avg.stat_type,
        avg.stat or '',
        avg.direction,
        avg.values,
        avg.last_updated or math_ceil(fiber.time()),
    }
end

local flow_expired = function(args,tuple)
    -- Flows are stored with millisecond precision
    local tuple_older_than_history = (tuple[1] < ((fiber.time() - args.max_history) * 1000))
    local tuple_older_than_day = false
    if tuple[2] then
        tuple_older_than_day = (86400 * 1000) < (tuple[2] - tuple[1])
    end


    -- if tuple_older_than_history or tuple_older_than_day then
    --     log.info('Tuple is expired with age ' .. (fiber.time() - (tuple[1] / 1000)) .. 's, max history is ' .. args.max_history)
    -- end
    return tuple_older_than_history or tuple_older_than_day
end

-- Special case so we don't remove the average bucket at timestamp 0
local bucket_expired = function(args,tuple)
    return tuple[1] < (fiber.time() - args.max_history)
end

local member_flows_delete = function(space_id,args,tuple)
    box.space[space_id]:delete({tuple[1],tuple[3],tuple[4],tuple[5],tuple[6],tuple[7],tuple[8]})
end

local member_bucket_delete = function(space_id,args,tuple)
    box.space[space_id]:delete({tuple[1]})
end

-- Expire un-updated stats after a day
local avg_stat_expired = function(args,tuple)
    return tuple[5] < (fiber.time() - 86400)
end

local member_avg_stats_delete = function(space_id,args,tuple)
    box.space[space_id]:delete({tuple[1],tuple[2],tuple[3]})
end

local alert_expired = function(args,tuple)
    local alert = alert2table(tuple)
    local now = fiber.time()

    -- If alert was last updated more than 60s ago and active, then expire
    local expired = alert.active and now - alert.updated_ts > args.inactive_expiry_time
    return expired

end

local format_alert_details = function(alert)
    local pretty_format_str = tbl_concat({
        "Target: %(target_pretty)",
        "Attack Type: %(protocol_name_pretty)",
        "Condition: %(value_pretty) > %(threshold_pretty)",
        "Peak Target Traffic IN:      %(target_inbound_bps_pretty) / %(target_inbound_pps_pretty) / %(target_inbound_fps_pretty)",
        "Peak Target Traffic OUT:     %(target_outbound_bps_pretty) / %(target_outbound_pps_pretty) / %(target_outbound_fps_pretty)",
    },'\n')
    return pretty_format_str % alert.details

end

local member_alert_deactivate = function(space_id,args,tuple)
    local alert = alert2table(tuple)
    local now   = math_ceil(fiber.time())

    alert.active     = false
    alert.updated_ts = now
    alert.duration   = alert.updated_ts - alert.start_ts

    alert.details.attack_details = format_alert_details(alert)

    -- Update in db
    local spc_alerts          = box.space.alerts

    local alert_tuple = alert2tuple(alert)

    rPrint(alert)

    spc_alerts:delete({alert.start_ts,alert.direction,alert.target_type,alert.target})

    -- Dont show expired message for alert which hasn't been notified yet
    if alert.notified_start then
        if not alert.notified_end then
            if events.trigger('alert_inactive',alert.duration,alert.details) then
                alert.notified_end = true
            end
        end
    end
end

local setup_db = function()
    -- FLOWS: {{{Start Timestamp}, {End Timestamp}}, Src IP, Src Port, Dst Ip, Dst Port, Proto, Tos}, Subnet, IP, Direction
    box.schema.space.create('flows',{field_count=11,if_not_exists = true})
    box.space.flows:create_index('primary',{unique = true, type = 'HASH', parts = {1, 'NUM', 3, 'STR', 4, 'NUM', 5, 'STR', 6, 'NUM', 7, 'NUM', 8, 'NUM'}, if_not_exists = true})
    box.space.flows:create_index('by_end_ts',{unique = false, parts = {2, 'NUM', 3, 'STR', 4, 'NUM', 5, 'STR', 6, 'NUM', 7, 'NUM', 8, 'NUM'}, if_not_exists = true})
    box.space.flows:create_index('by_hash',{unique = false, parts = {3, 'STR', 4, 'NUM', 5, 'STR', 6, 'NUM', 7, 'NUM', 8, 'NUM'}, if_not_exists = true})
    box.space.flows:create_index('by_dst_ip',{unique = false, parts = {5, 'STR'}, if_not_exists = true})
    box.space.flows:create_index('by_src_ip',{unique = false, parts = {3, 'STR'}, if_not_exists = true})
    box.space.flows:create_index('by_dst_port',{unique = false, parts = {6, 'NUM'}, if_not_exists = true})
    box.space.flows:create_index('by_src_port',{unique = false, parts = {4, 'NUM'}, if_not_exists = true})
    box.space.flows:create_index('by_dir_subnet',{unique = false, parts = {9, 'STR',11,'NUM'}, if_not_exists = true})
    expirationd.run_task('expire_flows', box.space.flows.id, flow_expired, member_flows_delete, {max_history = config.max_history}, 1000, 360)

    -- Buckets: {Timestamp}, Data 
    box.schema.space.create('buckets',{field_count=2,if_not_exists = true})
    box.space.buckets:create_index('primary',{unique = true, type = 'HASH', parts = {1, 'NUM'}, if_not_exists = true})
    box.space.buckets:create_index('by_ts',{unique = true, parts = {1, 'NUM'}, if_not_exists = true})

    -- Delete moving average bucket on start
    -- box.space.buckets:delete({0})

    expirationd.run_task('expire_buckets', box.space.buckets.id, bucket_expired, member_bucket_delete, {max_history = config.max_history}, 1000, 360)

    -- Average Stats: {Stat_Type, Stat, Direction}, Value, Last Updated 
    box.schema.space.create('avg_stats',{field_count=5,if_not_exists = true})
    box.space.avg_stats:create_index('primary',{unique = true, type = 'HASH', parts = {1, 'STR', 2, 'STR', 3, 'NUM'}, if_not_exists = true})
    box.space.avg_stats:create_index('by_last_updated',{unique = false, parts = {5, 'NUM'}, if_not_exists = true})
    expirationd.run_task('expire_avg_stats', box.space.avg_stats.id, avg_stat_expired, member_avg_stats_delete, {}, 1000, 360)

    if box.space.alerts then
        box.space.alerts:drop()
    end

    -- Alerts: {{Start Timestamp}, {Direction, Target Type, Target}}, Active}, Value, Threshold, Duration, Notified Start, Notified End, Details, {Updated Timestamp}
    box.schema.space.create('alerts',{field_count=12,if_not_exists = true})
    box.space.alerts:create_index('primary',{unique = true, type = 'HASH', parts = {1, 'NUM', 2, 'NUM', 3, 'STR', 4, 'STR'}, if_not_exists = true})
    box.space.alerts:create_index('by_ts',{unique = false, parts = {1, 'NUM'}, if_not_exists = true})
    box.space.alerts:create_index('by_target',{unique = true, parts = {2, 'NUM', 3, 'STR', 4, 'STR', 5, 'NUM'}, if_not_exists = true})
    box.space.alerts:create_index('by_updated_ts',{unique = false, parts = {12, 'NUM'}, if_not_exists = true})

    -- This is important. We use alert expiry to set the alert to *inactive* and trigger an event
    expirationd.run_task('expire_alerts', box.space.alerts.id, alert_expired, member_alert_deactivate, {inactive_expiry_time = config.alert_expiry_time}, 10, config.alert_expiry_time)

end


local ipfix_listener = function(port,channel)

    -- Bind to configured ports
    local sock = socket('AF_INET','SOCK_DGRAM', 'udp')
    sock:setsockopt(proto.UDP,'SO_REUSEADDR',true)
    sock:bind("0.0.0.0",port)

    -- Set fiber listener name
    local self = fiber.self()
    self:name("ipfix/listener-port-" .. port)

    local max_flow_packet_length = config.max_flow_packet_length
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

local get_value_mt = function(tab)
    if not tab then
        tab = {}
    end
    setmetatable(tab, { __index = function(table,key)
        -- IDX 1-3 = Normal values + short averages
        -- IDX 4-6 = Long averages
        -- If index is > 3 then the default value is table[idx - 3] if set
        -- Otherwise the default value is 0
        if key > 3 then
            local def = table[key-3]
            if def then
                return def
            end
        end
        return 0 
    end })

    return tab
end

local ipfix_aggregator = function(ipfix_channel,aggregate_channel)
    -- Set fiber listener name
    local self = fiber.self()
    self:name("ipfix/aggregator")

    
    local decode_icmp_type = function(type_raw)
        local code = type_raw.value % 256
        local typ = (type_raw.value - code) / 256

        local name = 'unknown'
        local match_type = icmp_types[typ]

        if type(match_type) == 'table' then
            -- Lua uses 1-indexed tables so add 1 (since codes start at 0)
            if match_type[code+1] ~= nil then
                name = match_type[code+1]
            end
        else
            name = match_type
        end

        return {name,typ,code}
    end

    local decode_tcp_flags = function(flags_raw)
        local flags = {} 

        for _,flag in ipairs(tcp_flags_iter) do
            if bit_band(flag[2],flags_raw) == flag[2] then
                tbl_insert(flags,{flag[1],flag[2]})
            end
        end

        return flags
    end

    local status_active            = 1

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

    local bucket = {}
    local last_bucket_time = 0

    local aggregate_stat = function(store,typ,stat,values)
        if not store[typ] then
            store[typ] = {}
        end

        -- If stat is a table then someone omitted the stat variable
        -- Assume stat = typ and values = stat
        if type(stat) == 'table' then
            values = stat
            stat   = typ
        end
            
        local storage = store[typ][stat]
        if not storage then
            storage = get_value_mt()
        end

        for key, value in ipairs(values) do
            storage[key] = storage[key] + value
        end

        store[typ][stat] = storage
    end

    local packets, bits, flows = 0,0,0

    while 1 == 1 do
        local now = math_ceil(fiber.time())
        local bucket_time = now - now % bucket_length

        -- Reset bucket if we're switching to a new one
        if bucket_time ~= last_bucket_time then
            if not aggregate_channel:put({last_bucket_time,bucket},config.fiber_channel_timeout) then
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
                local src_subnet   = in_subnet(src_ip)
                local dst_subnet   = in_subnet(dst_ip)

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

local bucket_monitor = function(aggregate_channel,graphite_channel,alert_channel)
    local self = fiber.self()
    self:name("ipfix/bucket-monitor")

    local bucket_length  = config.bucket_length
    local active_timeout = config.active_timeout
    local idle_timeout   = config.idle_timeout

    -- Time over which to apply Exponentially Weighted Moving Average
    local average_calculation_period = config.average_calculation_period

    -- Delay before we start applying percentage based thresholds to historical data
    local initial_delay = (average_calculation_period * 3)

    log.info('Calculating moving averages over a ' .. average_calculation_period .. 's period')

    local started = fiber.time()

    local spc_buckets = box.space.buckets
    local spc_avg_stats = box.space.avg_stats
    
    local thresholds = config.thresholds

    while 1 == 1 do
        local bucket_data = aggregate_channel:get() 
        local bucket_ts,bucket_stats = bucket_data[1], bucket_data[2]

        local now = fiber.time()

        local graphite_output = {}
        
        if bucket_ts ~= nil and bucket_ts ~= 0 then
            -- Put bucket into space for historical monitoring
            spc_buckets:replace({bucket_ts,bucket_stats})

            -- For each direction
            for direction, stat_types in ipairs(bucket_stats) do
                -- For each type
                for stat_type, stats in pairs(stat_types) do
                    local submit_to_graphite = false

                    -- Only submit to graphite for specific stat types
                    if stat_type == 'global' 
                        or stat_type == 'ip' 
                        or stat_type == 'subnet' 
                        or stat_type == 'protocol'
                        or stat_type == 'port'
                        or stat_type == 'tcp_flag'
                        or stat_type == 'icmp_typecode' then
                        submit_to_graphite = true
                    end

                    if true then
                        for stat, values in pairs(stats) do

                            -- Set values metatable since this is not 'transmitted' in fiber ipc channels
                            local values = get_value_mt(values)

                            local sanitized_stat_name = tostring(stat):lower():gsub('/','_'):gsub('%.','_')

                            -- If these are equal then the graphite path would be stat_type.stat_type which we dont want
                            if sanitized_stat_name == stat_type then
                                sanitized_stat_name = ''
                            end

                            local direction_str = direction_name(direction)

                            -- Submit statistic to graphite
                            local graphite_name = tbl_concat({
                                'flow',
                                stat_type:lower(),
                                sanitized_stat_name,
                                direction_str,
                            },'.'):gsub('%.%.','.')


                            if submit_to_graphite then
                                -- We don't need ridiculous decimal precision here and the numbers are large
                                -- So lets just ceil the values instead of doing some ridiculous accurate rounding
                                graphite_channel:put({graphite_name .. '.bps',math_ceil(values[1]),bucket_ts})
                                graphite_channel:put({graphite_name .. '.pps',math_ceil(values[2]),bucket_ts})
                                graphite_channel:put({graphite_name .. '.fps',math_ceil(values[3]),bucket_ts})
                            end

                            -- Get average stat
                            -- {Stat_Name, Direction}, Value, Last Updated
                            local avg_record = avg2table(spc_avg_stats:get({
                                stat_type,
                                sanitized_stat_name,
                                direction,
                            }))

                            local avg_values

                            -- Average stat hasn't been set yet, use its' current values
                            if avg_record == nil then
                                avg_values = values
                            else
                                avg_values = get_value_mt(avg_record.values)
                            end

                            -- Calculate exponential moving average (http://en.wikipedia.org/wiki/Moving_average#Application_to_measuring_computer_performance) 
                            local fast_exp_value = math.exp(-bucket_length/average_calculation_period)
                            local slow_exp_value = math.exp(-bucket_length/(average_calculation_period * 30))

                            -- Fast moving average, used for graphing
                            avg_values[1] = values[1] + fast_exp_value * (avg_values[1] - values[1])
                            avg_values[2] = values[2] + fast_exp_value * (avg_values[2] - values[2])
                            avg_values[3] = values[3] + fast_exp_value * (avg_values[3] - values[3])

                            -- Slow moving average, used for historical heuristic thresholding
                            avg_values[4] = values[1] + slow_exp_value * (avg_values[4] - values[1])
                            avg_values[5] = values[2] + slow_exp_value * (avg_values[5] - values[2])
                            avg_values[6] = values[3] + slow_exp_value * (avg_values[6] - values[3])

                            if submit_to_graphite then
                                graphite_channel:put({graphite_name .. '.avg_bps',math_ceil(avg_values[1]),bucket_ts})
                                graphite_channel:put({graphite_name .. '.avg_pps',math_ceil(avg_values[2]),bucket_ts})
                                graphite_channel:put({graphite_name .. '.avg_fps',math_ceil(avg_values[3]),bucket_ts})
                            end

                            -- If thresholds for this stat type are configured
                            if thresholds[direction_str] and thresholds[direction_str][stat_type] and
                              thresholds[direction_str][stat_type][stat] then
                                local threshold_values = thresholds[direction_str][stat_type][stat]

                                -- Check if we've broken 'absolute' thresholds for each metric
                                for offset,metric in ipairs(metric_reverse) do
                                    if threshold_values[metric] and threshold_values[metric].abs < avg_values[offset] then 
                                        local broken = {
                                            metric    = metric,
                                            stat_type = stat_type,
                                            stat      = stat,
                                            value     = avg_values[offset],
                                            threshold = threshold_values[metric].abs,
                                            direction = direction,
                                        }
                                        alert_channel:put({broken,bucket_stats})
                                    end
                                end

                                -- Perform heuristic thresholding based on historical moving average
                                if now - started > initial_delay then
                                    for offset,metric in ipairs(metric_reverse) do
                                        local long_offset = 3 + offset
                                        if threshold_values[metric] and threshold_values[metric].pct then
                                            local threshold = (avg_values[long_offset] * (threshold_values[metric].pct / 100))
                                            if avg_values[offset] > (avg_values[long_offset] * (threshold_values[metric].pct / 100)) then
                                                local broken = {
                                                    metric    = metric,
                                                    stat_type = stat_type,
                                                    stat      = stat,
                                                    value     = avg_values[offset],
                                                    threshold = threshold,
                                                    direction = direction,
                                                }
                                                alert_channel:put({broken,bucket_stats})
                                            end
                                        end
                                    end
                                else
                                    lp.dequeue('We dont have enough history for heuristic thresholding, using absolute thresholds only...',10)
                                end
                            end

                            local stat_table = {
                                stat_type = stat_type,
                                stat      = sanitized_stat_name,
                                direction = direction,
                                values    = avg_values,
                            }

                            spc_avg_stats:replace(avg2tuple(stat_table))
                        end
                    end
                end
            end
        end
        fiber.sleep(0.1)
    end
end

local new_bucket_alerter = function(alert_channel,graphite_channel)
    local self = fiber.self()
    self:name("ipfix/new_bucket-alerter")

    local spc_buckets = box.space.buckets
    local spc_alerts = box.space.alerts
    local spc_alerts_by_target = spc_alerts.index.by_target

    local bucket_length = config.bucket_length

    local attack_protocol_ratio = config.attack_protocol_ratio
    local alert_active_time     = config.alert_active_time

    while 1 == 1 do
        local alert_stats = alert_channel:get()

        if alert_stats then
            local alert, stats = unpack(alert_stats)
            local now = math_ceil(fiber.time())


            -- Get attack details from active stats (these may be used to identify target)
            local stats_directed = stats[alert.direction]

            -- This is the number of the metric that broke the threshold
            local metric_num = metric[alert.metric]


            -- Identify target from threshold data
            if alert.stat_type ~= 'subnet' then
                log.info('Alert types other than "subnet" are not supported!')
            else
                log.info('Alert triggered on subnet ' .. alert.stat)

                -- Check if active alert already exists towards this target
                local db_alert_search = {
                    alert.direction,
                    'subnet',
                    alert.stat,
                    1,
                }

                log.info('Searching for DB alert with these fields: ' .. json_encode(db_alert_search))
                local db_alert = alert2table(spc_alerts_by_target:get(db_alert_search))

                -- If alert exists in DB, use as base
                if db_alert then
                    log.info('Active alert to target already exists in db...')
                    alert = db_alert
                    alert.duration = now - alert.start_ts
                else
                    alert.details        = {}
                    alert.target         = alert.stat
                    alert.target_type    = 'subnet'
                    alert.start_ts       = now
                    alert.active         = true
                    alert.duration       = 0
                    alert.notified_start = false
                    alert.notified_end   = false
                    alert.details.metric = alert.metric
                end

                alert.details.match_metric = stats_directed.subnet[alert.target][metric_num]
                alert.details.match_ratio = attack_protocol_ratio * alert.details.match_metric

                alert.updated_ts = now


                local proto_stat_name = tbl_concat({
                    'protocol',
                    alert.target_type,
                    alert.target,
                },'_')

                local tcp_flag_stat_name = tbl_concat({
                    'tcp',
                    'flag',
                    alert.target_type,
                    alert.target,
                },'_')

                local icmp_type_stat_name = tbl_concat({
                    'icmp',
                    'typecode',
                    alert.target_type,
                    alert.target,
                },'_')


                -- Calculate traffic profile, this compares to the total traffic of 'global', or 'subnet', or 'host'
                for _, cur_proto in ipairs(proto_iter) do
                    local proto_name, proto_num = unpack(cur_proto)

                    if stats_directed[proto_stat_name][proto_name] then
                        local proto_stat = stats_directed[proto_stat_name][proto_name][metric_num]

                        -- If stat is more than e.g. '85%' of the target total traffic levels
                        if proto_stat > alert.details.match_ratio then
                            alert.details.protocol      = proto_num
                            alert.details.protocol_name = proto_name:upper()
                            alert.details.protocol_certainty = ((proto_stat / alert.details.match_metric) * 100)
                            log.info('Protocol is ' .. alert.details.protocol_name .. ' with certainty ' .. tostring(alert.details.protocol_certainty))
                        end
                    end
                end

                if alert.details.protocol and alert.details.protocol == proto.TCP then
                    log.info('TCP attack detected, narrowing down TCP flags...')

                    for _, cur_flag in ipairs(tcp_flags_iter) do
                        local flag_name, flag_num = unpack(cur_flag)
                        if stats_directed[tcp_flag_stat_name] and stats_directed[tcp_flag_stat_name][flag_name] then
                            local tcp_flag_stat = stats_directed[tcp_flag_stat_name][flag_name][metric_num]
                            -- This is a TCP attack - if more than match_ratio TCP traffic
                            -- matches a specific flag, then this is a TCP flag based attack
                            if tcp_flag_stat > alert.details.match_ratio then
                                alert.details.tcp_flag   = flag_num
                                alert.details.protocol_certainty = ((tcp_flag_stat / alert.details.match_metric) * 100)
                                alert.details.protocol_name      = tbl_concat({alert.details.protocol_name,flag_name},' ')
                            end
                        end
                    end 
                elseif alert.details.protocol and alert.details.protocol == proto.ICMP then
                    -- We dont have reverse records for ICMP since it can be a multidimensional table
                    -- Iterate over the ICMP info for this bucket instead, this is probably quick enough
                    local icmp_table = stats_directed[icmp_type_stat_name]
                    if icmp_table then
                        for icmp_name, icmp_stats in pairs(icmp_table) do
                            local icmp_stat = icmp_stats[metric_num]
                            if icmp_stat > alert.details.match_ratio then
                                alert.details.icmp_type_name     = icmp_name
                                alert.details.protocol_certainty = ((icmp_stat / alert.details.match_metric) * 100)
                                alert.details.protocol_name      = tbl_concat({alert.details.protocol_name,icmp_name:upper()},' ')
                            end
                        end 
                    end
                end

                if not alert.details.peak_target_inbound then
                    alert.details.peak_target_inbound  = get_value_mt()
                end
                if not alert.details.peak_target_outbound then
                    alert.details.peak_target_outbound = get_value_mt()
                end
                if not alert.details.peak_target_unknown then
                    alert.details.peak_target_unknown  = get_value_mt()
                end

                -- Track target traffic rates for duration of alert
                for dir_num,dir_name in ipairs(direction_reverse) do
                    local peak_name = 'peak_target_'..dir_name
                    local target_stats

                    if stats[dir_num] and stats[dir_num][alert.target_type] then
                        target_stats = stats[dir_num][alert.target_type][alert.target]
                    end


                    for offset,metric in ipairs(metric_reverse) do
                        local metric_name = 'target_'..dir_name .. '_' .. metric .. '_pretty'

                        if target_stats then
                            local value = target_stats[offset]
                            if value then
                                if value > alert.details[peak_name][offset] then
                                    alert.details[peak_name][offset] = value
                                    alert.details[metric_name] = pretty_value(value,offset)
                                end
                            else
                                -- If it's not already set then set the target metric to 0
                                if not alert.details[metric_name] then
                                    alert.details[metric_name] = pretty_value(0,offset)
                                end
                            end
                        else
                            alert.details[metric_name] = pretty_value(0,offset)
                        end
                    end
                end
                
                log.info('Generating details...')
                alert.details.direction_name            = direction_name(alert.direction)
                alert.details.duration_pretty           = pretty_duration(alert.duration)
                alert.details.target_pretty             = alert.target or 'Unknown'
                alert.details.direction_name_pretty     = uc_first(alert.details.direction_name)
                alert.details.start_time_pretty         = os.date("!%a, %d %b %Y %X GMT",alert.start_ts)
                alert.details.metric_pretty             = alert.details.metric:upper()
                alert.details.value_pretty              = pretty_value(alert.value,metric_num)
                alert.details.threshold_pretty          = pretty_value(alert.threshold,metric_num)
                alert.details.protocol_name_pretty      = alert.details.protocol_name or 'Unknown'
                alert.details.protocol_certainty_pretty = string.format('(%.1f%%)',alert.details.protocol_certainty or 0)

                -- Only use this when event expires, this is the *last* time we saw the anomaly
                alert.details.end_time_pretty           = os.date("!%a, %d %b %Y %X GMT",alert.updated_ts)

                local sanitized_target = tostring(alert.target):lower():gsub('/','_'):gsub('%.','_')
                local sanitized_protocol_name

                if alert.details.protocol_name then
                    sanitized_protocol_name = tostring(alert.details.protocol_name):lower():gsub(' ','_'):gsub('%.','_')
                else
                    sanitized_protocol_name = 'unknown'
                end


                if alert.duration >= alert_active_time then
                    log.info('Submitting to graphite...')
                    -- Submit alert status to graphite
                    local graphite_name = tbl_concat({
                        'flow',
                        'alert',
                        alert.target_type,
                        sanitized_target,
                        sanitized_protocol_name,
                        alert.details.metric:lower(),
                    },'.'):gsub('%.%.','.')

                    -- Submit 1 to graphite when in alert state
                    graphite_channel:put({graphite_name,1,now})
                end

                log.info('Formatting alert details...')
                alert.details.attack_details = format_alert_details(alert)

                if not alert.notified_start then
                    log.info('Triggering event...')
                    if events.trigger('alert_active',alert.duration,alert.details) then
                        alert.notified_start = true
                    end
                end

                -- Update stored alert in database
                local alert_tuple = alert2tuple(alert)
                spc_alerts:replace(alert_tuple)
            end
        else
            fiber.sleep(0.1)
        end
    end
end

local bucket_alerter = function(alert_channel)
    local self = fiber.self()
    self:name("ipfix/bucket-alerter")

    local spc_buckets = box.space.buckets
    local spc_alerts = box.space.alerts
    local spc_alerts_by_hash = spc_alerts.index.by_hash

    local bucket_length = config.bucket_length

    local attack_protocol_ratio = config.attack_protocol_ratio

    while 1 == 1 do
        local alert_stats = alert_channel:get()

        if alert_stats then
            local new_alert, stats = unpack(alert_stats)
            local now = math_ceil(fiber.time())

            -- Set new_alert active
            new_alert.active = true

            -- Check to see if we currently have an active matching new_alert
            -- If we do, increment the match counter
            local new_alert_hash = {
                new_alert.direction,
                new_alert.stat_type,
                new_alert.stat,
                new_alert.metric,
                1,
            }

            local alert = alert2table(spc_alerts_by_hash:get(new_alert_hash))

            -- If alert is already active, then update it
            if alert then
                alert.duration = now - alert.start_ts
                alert.value    = alert.value
            -- Otherwise create new alert ready for dissection
            else
                alert                = new_alert
                alert.start_ts       = now
                alert.duration       = 0
                alert.notified_start = false
                alert.notified_end   = false
                alert.details        = {}
            end

            alert.updated_ts = now

            -- Get attack details from active stats
            local stats_directed = stats[alert.direction]
            local metric_num = metric[alert.metric]

            -- Get total counter for this metric from bucket stats
            local total_metric = stats_directed.global.global[metric_num]
            local total_ratio  = attack_protocol_ratio * total_metric

            alert.target = nil

            -- Identify target
            if alert.stat_type == 'subnet' then
                alert.subnet = alert.stat

                -- If this is against a subnet we can reduce the number of table lookups
                -- We need to make instead of checking all IPs
                -- We know the subnet so we use the ratio against the subnet traffic
                -- Rather than globally
                
                local subnet_metric = stats_directed.subnet[alert.subnet][metric_num]
                local subnet_ratio = attack_protocol_ratio * subnet_metric

                log.info('Alert triggered on subnet ' .. alert.subnet)
                local sub_lo,sub_high = ip.cidr_to_integer_range(alert.subnet)
                for i=sub_lo, sub_high do
                    local cur_ip = ip_addr_reverse[i]
                    if stats_directed.ip[cur_ip] then
                        local ip_stat = stats_directed.ip[cur_ip][metric_num]
                        if ip_stat > subnet_ratio then
                            alert.target = cur_ip
                            log.info('Alert triggered on host ' .. alert.target)
                        end
                    end
                end
                 
            -- If this is a single IP alert then we need to grab the subnet from the IP
            elseif alert.stat_type == 'ip' then
                alert.subnet = in_subnet(alert.stat)     
                alert.target = alert.stat

            -- If this was any other alert then we need to scan all known IP's to
            -- look for the target
            else
                for i, cur_ip in ipairs(ip_addr_reverse) do
                    if stats_directed.ip[cur_ip] then
                        local ip_stat = stats_directed.ip[cur_ip][metric_num]
                        if ip_stat > total_ratio then
                            local ip_metric = stats_directed.ip[cur_ip][metric_num]
                            alert.target = cur_ip
                            alert.subnet = in_subnet(cur_ip)
                        end
                    end
                end
            end

            local proto_stat_name     = 'protocol'
            local tcp_flag_stat_name  = 'tcp_flag'
            local icmp_type_stat_name = 'icmp_typecode'

            -- Attempt to calculate ratios above which we know the type of traffic
            -- dependent on the smallest aggregation (i.e. if we know attacked host, use that)
            if alert.target then
                local target        = alert.target
                local metric_value  = stats_directed.ip[target][metric_num]
                alert.match_ratio   = attack_protocol_ratio * metric_value
                alert.match_metric  = metric_value
                alert.match_type    = 'target'
                proto_stat_name     = 'protocol_ip_'..target
                tcp_flag_stat_name  = 'tcp_flag_ip_'..target
                icmp_type_stat_name = 'icmp_typecode_ip_'..target

            elseif alert.subnet then
                local subnet        = alert.subnet
                local metric_value  = stats_directed.subnet[subnet][metric_num]
                alert.match_ratio   = attack_protocol_ratio * metric_value
                alert.match_metric  = metric_value
                alert.match_type    = 'subnet'
                proto_stat_name     = 'protocol_subnet_'..subnet
                tcp_flag_stat_name  = 'tcp_flag_subnet_'..subnet
                icmp_type_stat_name = 'icmp_typecode_subnet_'..subnet
            else
                alert.match_ratio   = total_ratio
                alert.match_metric  = total_metric
                alert.match_type    = 'global'
            end

            local details = alert.details

            -- TODO: Clean all of this Up, must be less verbose way of doing this

            -- Calculate traffic profile
            for _, cur_proto in ipairs(proto_iter) do
                local proto_name, proto_num = unpack(cur_proto)

                if stats_directed[proto_stat_name][proto_name] then
                    local proto_stat = stats_directed[proto_stat_name][proto_name][metric_num]
                    if proto_stat > alert.match_ratio then
                        alert.protocol           = proto_num
                        alert.details.protocol   = proto_num
                        alert.protocol_name      = proto_name:upper()
                        alert.protocol_certainty = ((proto_stat / alert.match_metric) * 100)
                    end
                end
            end

            if alert.protocol and alert.protocol == proto.TCP then
                log.info('TCP attack detected, narrowing down TCP flags...')
                local match_metric = alert.match_metric
                local match_ratio  = attack_protocol_ratio * match_metric

                for _, cur_flag in ipairs(tcp_flags_iter) do
                    local flag_name, flag_num = unpack(cur_flag)
                    if stats_directed[tcp_flag_stat_name] and stats_directed[tcp_flag_stat_name][flag_name] then
                        local tcp_flag_stat = stats_directed[tcp_flag_stat_name][flag_name][metric_num]
                        -- This is a TCP attack - if more than match_ratio TCP traffic
                        -- matches a specific flag, then this is a TCP flag based attack
                        if tcp_flag_stat > match_ratio then
                            alert.details.tcp_flag   = flag_num
                            alert.protocol_certainty = ((tcp_flag_stat / match_metric) * 100)
                            alert.protocol_name      = tbl_concat({alert.protocol_name,flag_name},' ')
                        end
                    end
                end 
            elseif alert.protocol and alert.protocol == proto.ICMP then
                -- We dont have reverse records for ICMP since it can be a multidimensional table
                -- Iterate over the ICMP info for this bucket instead, this is probably quick enough
                local icmp_table = stats_directed[icmp_type_stat_name]
                for icmp_name, icmp_stats in pairs(icmp_table) do
                    local icmp_stat = icmp_stats[metric_num]
                    if icmp_stat > alert.match_ratio then
                        alert.details.icmp_type_name = icmp_name
                        alert.protocol_name  = tbl_concat({alert.protocol_name,icmp_name:upper()},' ')
                        alert.protocol_certainty = ((icmp_stat / alert.match_metric) * 100)
                    end
                end 
            end

            if not details.peak_global_inbound then
                details.peak_global_inbound  = get_value_mt()
            end
            if not details.peak_global_outbound then
                details.peak_global_outbound = get_value_mt()
            end
            if not details.peak_global_unknown then
                details.peak_global_unknown  = get_value_mt()
            end

            -- Track global traffic rates for duration of alert
            for offset,metric in ipairs(metric_reverse) do
                for dir_num,dir_name in ipairs(direction_reverse) do
                    local peak_name = 'peak_global_'..dir_name
                    if stats[dir_num].global then
                        local value = stats[dir_num].global.global[offset]
                        if value > details[peak_name][offset] then
                            log.info('New Peak ' .. dir_name .. ' for metric ' .. metric .. ': ' .. value .. ' > ' .. details[peak_name][offset])
                            details[peak_name][offset] = value
                            details['global_' .. dir_name .. '_' .. metric .. '_pretty'] = pretty_value(details[peak_name][offset],offset)
                        end
                    else
                        details['global_' .. dir_name .. '_' .. metric .. '_pretty'] = pretty_value(0,offset)
                    end
                end
            end

            if not details.peak_target_inbound then
                details.peak_target_inbound  = get_value_mt()
            end
            if not details.peak_target_outbound then
                details.peak_target_outbound = get_value_mt()
            end
            if not details.peak_target_unknown then
                details.peak_target_unknown  = get_value_mt()
            end

            -- Track target traffic rates for duration of alert
            for dir_num,dir_name in ipairs(direction_reverse) do
                local peak_name = 'peak_target_'..dir_name
                local target_stats

                if alert.target ~= nil then
                    if stats[dir_num].ip then
                        target_stats = stats[dir_num].ip[alert.target]
                        log.info('Alert has target ' .. alert.target)
                    end
                elseif alert.subnet ~= nil then
                    if stats[dir_num].subnet then
                        target_stats = stats[dir_num].subnet[alert.subnet]
                        log.info('Alert has target ' .. alert.subnet)
                    end
                end


                for offset,metric in ipairs(metric_reverse) do
                    local metric_name = 'target_'..dir_name .. '_' .. metric .. '_pretty'

                    if target_stats then
                        local value = target_stats[offset]
                        if value then
                            if value > details[peak_name][offset] then
                                details[peak_name][offset] = value
                                details[metric_name] = pretty_value(value,offset)
                            end
                        else
                            -- If it's not already set then set the target metric to 0
                            if not details[metric_name] then
                                details[metric_name] = pretty_value(0,offset)
                            end
                        end
                    else
                        details[metric_name] = pretty_value(0,offset)
                    end
                end
            end

            if not details.protocol_name then
                details.protocol_name = {}
            end

            -- Attempt to get current averages
            local avg_bucket = bucket2table(spc_buckets:get{0})

            -- EWMA: local avg_target_exp_value = math.exp(-bucket_length/300)

            if avg_bucket then
                local avg_directed = avg_bucket.data[alert.direction] 
                local avg_stats, global_stats

                if avg_directed then
                    global_stats = avg_directed.global.global
                    if alert.target ~= nil then
                        if alert.details.protocol ~= nil then
                            local metric = proto_reverse[alert.details.protocol]
                            avg_stats = avg_directed['protocol_ip_'..alert.target][metric]
                        else
                            avg_stats = avg_directed.ip[alert.target]
                        end
                    elseif alert.subnet ~= nil then
                        if alert.details.protocol ~= nil then
                            local metric = proto_reverse[alert.details.protocol]
                            avg_stats = avg_directed['protocol_subnet_'..alert.subnet][metric]
                        else
                            avg_stats = avg_directed.subnet[alert.subnet]
                        end
                    end
                else
                    log.info('Couldnt find average stats for direction ' .. direction_name(alert.direction))
                end

                for offset,metric in ipairs(metric_reverse) do
                    if not details['avg_directed_' .. metric] then
                        details['avg_directed_' .. metric] = 0
                    end
                    if not details['avg_global_' .. metric] then
                        details['avg_global_' .. metric] = 0
                    end

                    if avg_stats then
                        local value = avg_stats[offset]
                        local avg_value = details['avg_directed_' .. metric]
                        avg_value = (avg_value + value) / 2
                        -- EWMA: avg_value = value + avg_target_exp_value * (avg_value - value)

                        details['avg_directed_' .. metric .. '_pretty'] = pretty_value(avg_value,offset)
                        details['total_directed_' .. metric .. '_pretty'] = pretty_value(avg_value * alert.duration,metric_totals[metric])
                    else
                        details['avg_directed_' .. metric .. '_pretty'] = pretty_value(0,offset)
                        details['total_directed_' .. metric .. '_pretty'] = pretty_value(0,offset) 
                    end

                    if global_stats then
                        local value = global_stats[offset]
                        local avg_value = details['avg_global_' .. metric]
                        avg_value = (avg_value + value) / 2
                        -- EWMA: avg_value = value + avg_target_exp_value * (avg_value - value)

                        details['avg_global_' .. metric .. '_pretty'] = pretty_value(avg_value,offset)
                    else
                        details['avg_global_' .. metric .. '_pretty'] = pretty_value(0,offset) 
                    end
                end
            end

            alert.direction_name              = direction_name(alert.direction)
            details.duration_pretty           = pretty_duration(alert.duration)
            details.subnet_pretty             = alert.subnet or 'Unknown'
            details.direction_name_pretty     = uc_first(alert.direction_name)
            details.start_time_pretty         = os.date("!%a, %d %b %Y %X GMT",alert.start_ts)
            details.metric_pretty             = alert.metric:upper()
            details.value_pretty              = pretty_value(alert.value,metric_num)
            details.threshold_pretty          = pretty_value(alert.threshold,metric_num)
            details.protocol_certainty_pretty = string.format('(%.1f%%)',alert.protocol_certainty or 0)

            local new_protocol = false

            -- Check if this is a new protocol
            if alert.protocol_name and not details.protocol_name[alert.protocol_name] then
                new_protocol = true
                details.protocol_name[alert.protocol_name] = details.protocol_certainty_pretty
            end

            local unique_proto_names = dedup_keys(details.protocol_name,true)
            if #unique_proto_names > 0 then
                details.protocol_name_pretty      = tbl_concat(unique_proto_names,', ')
            else
                details.protocol_name_pretty      = 'Unknown'
            end

            -- Only use this when event expires, this is the *last* time we saw the anomaly
            details.end_time_pretty           = os.date("!%a, %d %b %Y %X GMT",alert.updated_ts)


            -- Name this alert for easier visibility
            if not details.name_pretty then
                details.name_pretty = get_consistent({
                    alert.direction,
                    alert.stat_type,
                    alert.stat,
                    alert.metric,
                    alert.start_ts,
                },config.alert_names)
            end

            -- ENDTODO: Clean all of this Up, must be less verbose way of doing this
            
            if not alert.target then
                alert.target = nil
            else
                if details.target == nil then
                    details.target = {}
                end
                details.target[alert.target] = true
                details.target_pretty = tbl_concat(dedup_keys(details.target),', ')
            end

            alert.details = details
            alert.details.attack_details = format_alert_details(alert)

            if not alert.notified_start then
                if events.trigger('alert_active',alert.duration,alert.details) then
                    alert.notified_start = true
                end
            elseif new_protocol then
                events.trigger('alert_new_protocol',alert.duration,alert.details)
            end

            -- Alerts: {{Start Timestamp}, {Direction, Stat Type, Stat, Metric}}, Active}, Value, Threshold, Duration, Notified Start, Notified End, {Updated Timestamp}
            local added_alert = spc_alerts:replace(alert2tuple(alert))
        end
        fiber.sleep(0.1)
    end
end

local graphite_submitter = function(graphite_channel)
    local self = fiber.self()
    self:name("ipfix/graphite-submitter")

    local pending = 0
    local output = ''
    local conn_info = socket.getaddrinfo(config.graphite_host,'2010')
    local graphite_host = conn_info[1].host
    local graphite_port = config.graphite_port

    if not graphite_host or not graphite_port then
        log.info('Disabling graphite submission, no host or port configured!')
        return
    else
        log.info('Resolved graphite host to ' .. graphite_host .. ':' .. graphite_port)
    end

    local graphite = socket('AF_INET', 'SOCK_DGRAM', 'udp')

    while 1 == 1 do
        local to_submit = graphite_channel:get(1.0)
        if to_submit ~= nil then
            pending = pending + 1
            output = output .. tbl_concat(to_submit,' ') .. "\n"
        end

        if pending >= 5 or to_submit == nil then
            local sent = graphite:sendto(graphite_host,graphite_port,output)
            if not sent then
                log.error('Metric output to Graphite at ' .. graphite_host .. ':' .. graphite_port .. ' failed! - ' .. graphite:error())
            end
            pending = 0
            output  = ''
            fiber.sleep(0.001)
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
        log.info("Saving IPFIX templates...")
        ipfix.save_templates(config.ipfix_tpl_cache_file)
    end
end

local stat_generator = function(graphite_channel)
    local self = fiber.self()
    self:name("ipfix/stat-generator")

    while 1 == 1 do
        local now = math_ceil(fiber.time())

        -- Submit size of each box to graphite
        for k, v in box.space._space:pairs() do
            local space_name = v[3]
            if box.space[space_name].index[0] ~= nil then
                tuple_count = box.space[space_name].index[0]:count()
            else
                tuple_count = 0
            end

            graphite_channel:put({'flow.stats.space.'..space_name..'.tuple_count',math_ceil(tuple_count),now})
        end

        for field, value in pairs(box.slab.info()) do
            if type(value) == "number" then
                graphite_channel:put({'flow.stats.box.slab.'..field,math_ceil(value),now})

            else
                if field == 'slabs' then
                    -- Submit each slab size plus item count and used
                    for _, slabvar in ipairs(value) do
                        local stat_path = 'flow.stats.box.slab.slabs.'..tostring(slabvar.item_size)
                        graphite_channel:put({stat_path .. '.count',slabvar.item_count,now})
                        graphite_channel:put({stat_path .. '.mem_free',slabvar.mem_free,now})
                        graphite_channel:put({stat_path .. '.mem_used',slabvar.mem_used,now})
                        graphite_channel:put({stat_path .. '.slab_count',slabvar.slab_count,now})
                        graphite_channel:put({stat_path .. '.slab_size',slabvar.slab_size,now})
                    end
                end
            end
        end
        for field, value in pairs(box.stat()) do
            if type(value) == "table" then
                local field = field:lower()
                if value.total then
                    graphite_channel:put({'flow.stats.box.stat.'..field..'.total',math_ceil(value.total),now})
                end
                if value.rps then
                    graphite_channel:put({'flow.stats.box.stat.'..field..'.rps',math_ceil(value.rps),now})
                end
            end
        end
        fiber.sleep(10)
    end
end

local start_fibers = function()
    -- Start listener for each unique listening port (we *can* have multiple sources per port)
    local ipfix_channel     = fiber.channel(config.fiber_channel_capacity or 1024)
    local aggregate_channel = fiber.channel(1024)
    local graphite_channel  = fiber.channel(8192)
    local alert_channel     = fiber.channel(1024)

    local bgsaver, aggregator, monitor, submitter, alerter, statter
    local listeners = {}

    while 1 == 1 do
        
        if not bgsaver or bgsaver.status() == 'dead' then
            log.info('(Re)starting background saver')
            bgsaver = fiber.create(ipfix_background_saver)
        end

        -- Write to ipfix_channel
        for _, port in ipairs(config.ports) do
            if not listeners[port] or listeners[port].status() == 'dead'  then
                log.info("(Re)starting IPFIX listener on port " .. port)
                listeners[port] = fiber.create(ipfix_listener,port,ipfix_channel)
            end
        end

        -- Read from ipfix_channel, write to aggregate_channel
        if not aggregator or aggregator.status() == 'dead' then
            log.info('(Re)starting aggregator')
            aggregator = fiber.create(ipfix_aggregator,ipfix_channel,aggregate_channel) 
        end

        -- Read from aggregate_channel, write to graphite_channel
        if not monitor or monitor.status() == 'dead' then
            log.info('(Re)starting monitor')
            monitor = fiber.create(bucket_monitor,aggregate_channel,graphite_channel,alert_channel)
        end

        -- Read from alert_channel
        if not alerter or alerter.status() == 'dead' then
            log.info('(Re)starting alerter')
            alerter = fiber.create(new_bucket_alerter,alert_channel,graphite_channel)
        end

        -- Write to graphite_channel
        if not statter or statter.status() == 'dead' then
            log.info('(Re)starting graphite statter')
            statter = fiber.create(stat_generator,graphite_channel)
        end

        -- Read from graphite_channel
        if not submitter or submitter.status() == 'dead' then
            log.info('(Re)starting graphite submitter')
            submitter = fiber.create(graphite_submitter,graphite_channel)
        end
        fiber.sleep(5)
    end
end

local start_http_server = function()
    local bucket_length = config.bucket_length

    log.info("Start HTTP Server on " .. config.http_host .. ":" .. config.http_port )
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

    server:route({ path = '/alerts' }, function(self)
        local out = {}
        for _,alert in box.space.alerts:pairs{} do
            tbl_insert(out,alert2table(alert))
        end
        return self:render{ json = out }
    end)
    
    server:route({ path = '/buckets', method='GET' }, function(self)
        local stat = self:stash('stat')
        local out = {}
        local newer = math_ceil(fiber.time() - 3600)
        local i = 1
        for _, bucket in box.space.buckets.index.by_ts:pairs({newer},{iterator = 'GT'}) do
            tbl_insert(out,bucket[1],bucket[2])
        end
        return self:render{ json = { buckets = out } }
    end)

    server:route({ path = '/avg-bucket', method='GET' }, function(self)
        return self:render{ json = { buckets = box.space.buckets:get({0})[2] } }
    end)

    server:route({ path = '/profile', method='GET' }, function(self)
        local msg
        if not ProFi.has_started or ProFi.has_finished then
            ProFi:start()
            msg = 'Started profiling...'
        else
            ProFi:stop()
            ProFi:writeReport()
            msg = 'Stopped profiling and wrote report to file!'
        end
        return self:render{ json = { msg = msg } }
    end)

    server:start()
end

load_config()
bootstrap_db()
setup_user()
setup_db()
load_ipfix()
fiber.create(start_fibers)
start_http_server()

