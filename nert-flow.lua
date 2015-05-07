#!/usr/bin/env tarantool
local os      = require("os")
local binutil = require("binutil")
local ipfix   = require("ipfix")
local ip      = require("ip")
local ceil    = math.ceil

local http    = require("http.server")
local fiber   = require("fiber")
local yaml    = require("yaml")
local json    = require("json")
local socket  = require("socket")


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
local elements = {}

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
    elements = constants.elements
    f:close()

    config.fiber_channel_timeout   = config.fiber_channel_timeout or 1
    config.fiber_channel_capacity  = config.fiber_channel_capacity or 1024
    config.fiber_channel_full_perc = config.fiber_channel_full_perc or 0.85
    config.ipfix_tpl_save_interval = config.ipfix_tpl_save_interval or 300
end

local load_ipfix = function()
    ipfix.configure(config,elements)
    ipfix.load_templates(config.ipfix_tpl_cache_file)
end

local bootstrap_db = function()
    box.cfg({
        listen = config.db_port or 3301,
        work_dir = config.work_dir or "./data",
    })
end

local setup_user = function()
    if not box.schema.user.exists('guest') then
        box.schema.user.create('guest', {password = box.info.server.uuid})
        box.schema.user.grant('guest','read,write,execute','universe')
    end
end

local setup_db = function()
    -- FLOWS: {Timestamp, Src IP, Src Port, Dst Ip, Dst Port, Proto, Tos}
    box.schema.space.create('flows',{field_count=7,if_not_exists = true})
    box.space.flows:create_index('primary',{unique = true, parts = {1, 'NUM', 2, 'STR', 3, 'NUM', 4, 'STR', 5, 'NUM', 6, 'NUM', 7, 'NUM'}, if_not_exists = true})

    -- SOURCES: {Source, Listen Port}, Name, Group, Options, Active
    box.schema.space.create('sources',{field_count=6,if_not_exists = true})
    box.space.sources:create_index('primary',{unique = true, parts = {1, 'STR', 2, 'NUM'}, if_not_exists = true})
    box.space.sources:create_index('by_group',{unique = false, parts = {4, 'NUM'}, if_not_exists = true})

    -- GROUPS: ID, Name, Options, Active
    box.schema.space.create('groups',{field_count=4,if_not_exists = true})
    box.space.groups:create_index('primary',{unique = true, parts = {1, 'NUM'}, if_not_exists = true})
    box.space.groups:create_index('by_name',{unique = true, parts = {2, 'STR'}, if_not_exists = true})
end

local source2table = function(source)
    return {
        name        = source[3],
        source_ip   = source[1],
        listen_port = source[2],
        group       = source[4],
        options     = source[5],
        active      = source[6],
    }
end

local source2tuple = function(source)
    return {
        source.source_ip,
        source.listen_port,
        source.name,
        source.group,
        source.options,
        source.active
    }
end

local group2table = function(group)
    return {
        id      = group[1],
        name    = group[2],
        options = group[3],
        active  = group[4],
    }
end

local group2tuple = function(group)
    return {
        group.id,
        group.name,
        group.options,
        group.active
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
        print(json.encode(sa))
        if packet then -- No packets ready to be received - do nothing
            -- Parse recieved packet header
            local parsed = {}

            local header, packet = ipfix.parse_header(packet)
            parsed.header = header

            -- Parse packet sets while we still have some
            while #packet > 0 do
                set, packet = ipfix.parse_set(packet)

                -- If this is a template set, then set its' template id in global templates
                if set.id == 2 then
                -- Otherwise this is an options template set, skip for now

                elseif set.id == 3 then
                    print("Options template detected, ignoring...")

                -- Otherwise add it to the table of sets to be used for flow records
                else
                    local new_flows = set.flows
                    -- If we have new flows, then 
                    if new_flows then
                        for i=1,#new_flows do

                            local channel_count = channel:count()

                            -- If channel is full then cache flows here and attempt submission later
                            if channel:is_full() then
                                print("DATA LOST - Fiber channel full. Please increase fiber_channel_capacity config setting above " .. channel_count .. "!")
                            else 
                                if channel_count > (config.fiber_channel_capacity * config.fiber_channel_full_perc) then
                                    print("Fiber channel is almost full (" .. channel_count .. "/" .. config.fiber_channel_capacity .. "), please check your fiber_channel_capacity setting!")
                                end

                                if not channel:put(new_flows[i],config.fiber_channel_timeout) then
                                    print("Error submitting to fiber channel")
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

local ipfix_aggregator = function(channel)
    -- Set fiber listener name
    local self = fiber.self()
    self:name("ipfix/aggregator")

    while 1 == 1 do
        local flow = channel:get()

        if flow then
            -- Retrieve flow start / end from second / millisecond fields
            local flow_start,flow_end, flow_duration

            if flow[150] and flow[151] then
                flow_start = flow[150].value
                flow_end   = flow[151].value
            elseif flow[152] and flow[153] then
                flow_start = ceil(flow[152].value / 1000)
                flow_end   = ceil(flow[153].value / 1000)
            else
                print("Flow packet with no identifiable flow start / end")
            end
        
            if flow_start ~= nil and flow_end ~= nil then
                flow_duration = flow_end - flow_start

                if flow_duration == 0 then
                    flow_duration = 1 -- Shortest flow duration is 1s
                end

                local flow_status = flow[136].value
                local observed_duration, observed_start, observed_end = flow_duration,flow_start,flow_end

                if flow_status == 1 then -- This flow has idled to timeout
                    -- If flow duration is longer than the idle timeout then this is idle_timeout worth of observations
                    if flow_duration > idle_timeout then
                        observed_duration = idle_timeout
                        observed_start = observed_end - idle_timeout
                    end
                elseif flow_status == 2 then -- This flow has active timeout
                    -- If flow duration is longer than the active timeout then this is active_timeout worth of observations
                    if flow_duration > active_timeout then
                        observed_duration = active_timeout
                        observed_start = observed_end - active_timeout
                    end
                else -- If this has expired for any other reason we need to work out when the last flow export for this was to calculate the observed_duration
                    if flow_duration > idle_timeout and flow_duration > active_timeout then
                        print("This is a long flow and was not active / idle timeout")
                    end
                end

                -- Calculate average bps / pps for the observed part of this flow
                local avg_bps = (flow[1].value / observed_duration) * 8
                local avg_pps = flow[2].value / observed_duration

                -- Generate the hash of this flow
                local ff = {
                    src_ip   = flow[8].value[1],  -- srcIPString
                    src_ipno = flow[8].value[2],  -- srcIPNumber
                    src_port = flow[7].value,     -- srcPort
                    dst_ip   = flow[12].value[1], -- dstIPString
                    dst_ipno = flow[12].value[2], -- dstIPNumber
                    dst_port = flow[11].value,    -- dstPort
                    proto    = flow[4].value,     -- proto
                    tos      = flow[5].value,     -- TOS
                }

                local flow_hash = md5.sumhexa(ff.src_ip .. ff.src_port .. ff.dst_ip .. ff.dst_port .. ff.proto ..ff.tos)

                ff.src_as         = flow[16].value
                ff.dst_as         = flow[17].value 

                if ff.src_as == 0 then
                    ff.src_as = local_as
                end
                if ff.dst_as == 0 then
                    ff.dst_as = local_as
                end

                ff.src_hostport   = ff.src_ip .. ':' .. ff.src_port
                ff.dst_hostport   = ff.dst_ip .. ':' .. ff.dst_port

                print(json.encode(ff))
            end
        else
            fiber.sleep(0.01)
        end
    end
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
    local ipfix_channel = fiber.channel(config.fiber_channel_capacity or 1024)

    for _, source in box.space.sources:pairs() do
        local source = source2table(source)
        local port = source.listen_port
        start_ipfix_listener(port,ipfix_channel)
    end
    fiber.create(ipfix_aggregator,ipfix_channel) 
    fiber.create(ipfix_background_saver)
end

local start_http_server = function()
    print("Start HTTP Server on " .. config.http_host .. ":" .. config.http_port )
    server = http.new(config.http_host, config.http_port, {app_dir = '..', cache_static = false})

    server:route({ path = '/' }, function(self)
        return self:redirect_to('/index.html')
    end)

    server:route({ path = '/config' }, function(self)
        local response = {
            config = config,
            time = math.ceil(fiber.time()),
        }
        return self:render{ json = response }
    end)

    server:route({ path = '/fibers' }, function(self)
        local response = fiber.info()
        return self:render{ json = response }
    end)

    server:route({ path = '/groups/', method='GET' }, function(self)
        local results = {}
        for _, group in box.space.groups:pairs{} do
            local sources = {}

            local response = group2table(group)
            
            for _, source in box.space.sources.index.by_group:pairs{response.id} do
                table.insert(sources,source2table(source))
            end

            response.sources = sources
            table.insert(results,response)
        end
        
        
        return self:render{ json = results }
    end)

    server:route({ path = '/groups/', method='PUT' }, function(self)
        local args = self:json()

        if args.active == nil then
            args.active = true
        end

        local result,err = box.space.groups:replace(group2tuple(args))
        local response = self:render{ json = result }
        if err ~= nil then
            response.status = 400
            response = err
        else 
            response.headers['Location'] = '/group/' .. args.name
            response.status = 201
        end
        return response
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
-- start_fibers()
start_http_server()

