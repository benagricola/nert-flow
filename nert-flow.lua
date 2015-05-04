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

function round(val, decimal)
  if (decimal) then
    return math.floor( (val * 10^decimal) + 0.5) / (10^decimal)
  else
    return math.floor(val+0.5)
  end
end

local config = {}

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
    box.space.flows:create_index('primary',{unique = true, parts = {1, 'NUM', 2, 'STR', 3, 'STR', 4, 'NUM', 5, 'NUM', 6, 'NUM', 7, 'NUM'}, if_not_exists = true})

    -- SOURCES: {Listen IP, Listen Port}, Name, Group, Options, Active
    box.schema.space.create('sources',{field_count=6,if_not_exists = true})
    box.space.sources:create_index('primary',{unique = true, parts = {1, 'STR', 2, 'NUM'}, if_not_exists = true})
    box.space.sources:create_index('by_group',{parts = {4, 'NUM'}, if_not_exists = true})

    -- GROUPS: ID, Name, Options, Active
    box.schema.space.create('groups',{field_count=4,if_not_exists = true})
    box.space.groups:create_index('primary',{unique = true, parts = {1, 'NUM'}, if_not_exists = true})
    box.space.groups:create_index('by_name',{unique = true, parts = {2, 'STR'}, if_not_exists = true})
end

local source2table = function(source)
    return {
        name        = source[3],
        listen_ip   = source[1],
        listen_port = source[2],
        options     = source[5],
        active      = source[6],
    }
end

local source2tuple = function(source)
    return {source.listen_ip,source.listen_port,source.name,
        source.group,source.options,source.active}
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
    return {group.id,group.name,group.options,group.active}
end

local start_fibers = function()

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

    server:route({ path = '/sources/', method='PUT' }, function(self)
        local args = self:json()

        if args.active == nil then
            args.active = true
        end
        local result,err = box.space.sources:replace(source2tuple(args))
        local response = self:render{ json = result }
        if err ~= nil then
            response.status = 400
            response = err
        else 
            response.headers['Location'] = '/source/' .. args.name
            response.status = 201
        end
        return response
    end)
    server:start()
end

load_config()
load_ipfix()
bootstrap_db()
setup_user()
setup_db()
start_fibers()
start_http_server()

