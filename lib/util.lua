local digest       = require('digest')
local digest_crc32 = digest.crc32
local digest_guava = digest.guava
local string       = require('string')
local str_format   = string.format
local str_upper    = string.upper
local str_gsub     = string.gsub
local table        = require('table')
local tbl_concat   = table.concat
local tbl_insert   = table.insert
local bit          = require('bit')
local bit_band     = bit.band
local math         = require('math')
local math_floor   = math.floor
local math_ceil    = math.ceil
local fiber        = require('fiber')
local fiber_time   = fiber.time
local _M = {}

local constants    = require("constants")
local tcp_flags     = constants.tcp_flags
local proto         = constants.proto
local direction     = constants.direction
local metric        = constants.metric 
local metric_totals = constants.metric_totals 
local flow_status   = constants.flow_status 
local icmp_types    = constants.icmp_types 

-- Define reverse mappings
local tcp_flags_reverse   = constants.tcp_flags_reverse
local tcp_flags_iter      = constants.tcp_flags_iter
local proto_reverse       = constants.proto_reverse
local proto_iter          = constants.proto_iter
local direction_reverse   = constants.direction_reverse 
local direction_iter      = constants.direction_iter
local flow_status_reverse = constants.flow_status_reverse
local flow_status_iter    = constants.flow_status_iter
local metric_reverse      = constants.metric_reverse 
local metric_totals_reverse = constants.metric_totals_reverse


-- Adds a string interpolation method using the mod sign (string % {replacements})
_M.interp = function(s, tab)
    return (str_gsub(s,'%%%(([%w_-]+)%)', function(w)
        return tab[w] or w
    end))
end
getmetatable('').__mod = _M.interp

function _M.get_consistent(hash_fields,buckets)
    local base_hash = digest_crc32(tbl_concat(hash_fields) .. fiber_time())

    local selected_bucket = digest_guava(base_hash,#buckets)

    return buckets[selected_bucket]
end

function _M.pretty_duration(duration)
    local pretty_table = {}

    -- Durations are in seconds
    -- If duration is more than an hour
    if duration > 3600 then
        hours = math_floor(duration / 3600)
        duration = duration - hours * 3600
        tbl_insert(pretty_table,str_format('%dh',hours))
    end

    if duration > 60 then
        minutes = math_floor(duration / 60)
        duration = duration - minutes * 60
        tbl_insert(pretty_table,str_format('%dm',minutes))
    end
    if duration > 0 then
        tbl_insert(pretty_table,str_format('%ds',duration))
    end

    return tbl_concat(pretty_table,' ')
end

function _M.pretty_value(value,typ)
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
    return str_format('%.2f %s', value / divider, unit)
end

function _M.uc_first(str)
    return (str:gsub("^%l", str_upper))
end

function _M.dedup_keys(input,use_values)
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

function _M.alert2table(alert)
    if alert == nil then
        return nil
    end
    local notified_start = alert[9] == 1
    local notified_end   = alert[10] == 1
    return {
        start_ts       = alert[1],
        direction      = alert[2],
        target_type    = alert[3],
        target         = alert[4],
        active         = alert[5] == 1,
        value          = alert[6],
        threshold      = alert[7],
        duration       = alert[8],
        notified_start = notified_start,
        notified_end   = notified_end,
        details        = alert[11],
        updated_ts     = alert[12],
    }
end

function _M.alert2tuple(alert)
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

function _M.flow2table(flow)
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

function _M.flow2tuple(flow)
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

function _M.bucket2table(bucket)
    if bucket == nil then
        return nil
    end
    return {
        ts   = bucket[1],
        data = bucket[2],
    }
end

function _M.bucket2tuple(bucket)
    if bucket == nil then
        return nil
    end

    return {
        bucket.ts,
        bucket.data,
    }
end

function _M.avg2table(avg)
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

function _M.avg2tuple(avg)
    if avg == nil then
        return nil
    end

    return {
        avg.stat_type,
        avg.stat or '',
        avg.direction,
        avg.values,
        avg.last_updated or math_ceil(fiber_time()),
    }
end

function _M.format_alert_details(alert)
    local pretty_format_str = tbl_concat({
        "Target: %(target_pretty)",
        "Attack Type: %(protocol_name_pretty)",
        "Condition: %(value_pretty) > %(threshold_pretty)",
        "Peak Target Traffic IN:      %(target_inbound_bps_pretty) / %(target_inbound_pps_pretty) / %(target_inbound_fps_pretty)",
        "Peak Target Traffic OUT:     %(target_outbound_bps_pretty) / %(target_outbound_pps_pretty) / %(target_outbound_fps_pretty)",
        "Peak Global Traffic IN:      %(global_inbound_bps_pretty) / %(global_inbound_pps_pretty) / %(global_inbound_fps_pretty)",
        "Peak Global Traffic OUT:     %(global_outbound_bps_pretty) / %(global_outbound_pps_pretty) / %(global_outbound_fps_pretty)",
    },'\n')
    return pretty_format_str % alert.details

end

function _M.get_value_mt(tab)
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

function _M.decode_icmp_type(type_raw)
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

function _M.decode_tcp_flags(flags_raw)
    local flags = {} 

    for _,flag in ipairs(tcp_flags_iter) do
        if bit_band(flag[2],flags_raw) == flag[2] then
            tbl_insert(flags,{flag[1],flag[2]})
        end
    end

    return flags
end

function _M.aggregate_stat(store,typ,stat,values)
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
        storage = _M.get_value_mt()
    end

    for key, value in ipairs(values) do
        storage[key] = storage[key] + value
    end

    store[typ][stat] = storage
end


return _M
