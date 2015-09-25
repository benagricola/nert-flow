local _M = {

    -- Define constants
    tcp_flags = {
        FIN = 1,
        SYN = 2,
        RST = 4,
        ACK = 8,
        URG = 32,
        ECE = 64,
        CWR = 128,
        NS  = 256,
    },

    proto = {
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
    },

    direction = {
        inbound  = 1,
        outbound = 2,
        unknown  = 3,
    },

    metric = {
        bps = 1,
        pps = 2,
        fps = 3,
    },

    metric_totals = {
        bps = 4,
        pps = 5,
        fps = 6,
    },

    flow_status = {
        idle_timeout   = 1,
        active_timeout = 2,
        ended          = 3,
        force_ended    = 4,
        lor_ended      = 5,
    },

    icmp_types = {
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
    },

    -- Define reverse and iter mappings
    tcp_flags_reverse   = {},
    tcp_flags_iter      = {},
    proto_reverse       = {},
    proto_iter          = {},
    direction_reverse   = {},
    direction_iter      = {},
    flow_status_reverse = {},
    flow_status_iter    = {},
    metric_reverse      = {},
    metric_iter         = {},
    metric_totals_reverse = {},
    metric_totals_iter  = {},
}

_M.tcp_flags_name = function(tcp_flags_num)
    if not tcp_flags_reverse[tcp_flags_num] then
        log.error('Unidentified TCP flag: ' .. tcp_flags_num)
    end
    return tcp_flags_reverse[tcp_flags_num] or 'unknown'
end

_M.proto_name = function(proto_num)
    if not proto_reverse[proto_num] then
        log.error('Unidentified protocol number: ' .. proto_num)
    end
    return proto_reverse[proto_num] or 'other'
end

_M.direction_name = function(direction_num) 
    return direction_reverse[direction_num] or 'unknown'
end

_M.flow_status_name = function(flow_status_num) 
    if not flow_status_reverse[flow_status_num] then
        log.error('Unidentified flow status: ' .. flow_status_num)
    end
    return flow_status_reverse[flow_status_num] or 'unknown'
end

for tcp_flags_name, tcp_flags_num in pairs(_M.tcp_flags) do
    _M.tcp_flags_reverse[tcp_flags_num] = tcp_flags_name
    tbl_insert(_M.tcp_flags_iter,{tcp_flags_name,tcp_flags_num})
end

for proto_name, proto_num in pairs(_M.proto) do
    _M.proto_reverse[proto_num] = proto_name
    tbl_insert(_M.proto_iter,{proto_name,proto_num})
end

for direction_name, direction_num in pairs(_M.direction) do
    _M.direction_reverse[direction_num] = direction_name
    tbl_insert(_M.direction_iter,{direction_name,direction_num})
end

for flow_status_name, flow_status_num in pairs(_M.flow_status) do
    _M.flow_status_reverse[flow_status_num] = flow_status_name
    tbl_insert(_M.flow_status_iter,{flow_status_name,flow_status_num})
end

for metric_name, metric_num in pairs(_M.metric) do
    _M.metric_reverse[metric_num] = metric_name
    tbl_insert(_M.metric_iter,{metric_name,metric_num})
end

for metric_totals_name, metric_totals_num in pairs(_M.metric_totals) do
    _M.metric_totals_reverse[metric_totals_num] = metric_totals_name
    tbl_insert(_M.metric_totals_iter,{metric_totals_name,metric_totals_num})
end

return _M
