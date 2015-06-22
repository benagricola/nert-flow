local binutil = require("binutil")
local lp      = require("logprint")
local log     = require("log")
local u8   = binutil.u8
local u16  = binutil.u16
local u32  = binutil.u32
local uvar = binutil.uvar
local bit_bor = bit.bor
local bit_lshift = bit.lshift

local json = require("json")

local _M = { templates = {}, config = { tpl_cache_file = nil } }

local type_map = {
    unsigned8  = uvar,
    unsigned16 = uvar,
    unsigned32 = uvar,
    unsigned64 = uvar,
    boolean = function (raw) return raw == 1 end,
    dateTimeSeconds = uvar,
    dateTimeMilliseconds = uvar,
    dateTimeMicroseconds = uvar,
    dateTimeNanoseconds = uvar,
    ipv4Address = function (raw) 
    local bin_ip = 0 
    for i=1,#raw, 1 do
        local bin_octet = u8(raw,i)
        bin_ip = bit_bor(bit_lshift(bin_octet, 8*(4-i) ), bin_ip)
    end

    local o1 = u8(raw,1)
    local o2 = u8(raw,2)
    local o3 = u8(raw,3)
    local o4 = u8(raw,4)
    if o1 == nil or o2 == nil or o3 == nil or o4 == nil then
        return nil
    end
    return { 
        string.format("%i.%i.%i.%i", o1,o2,o3,o4),
        bin_ip,
    } end,

    default = function (raw) return raw end,
}



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
function _M.configure(config,elements)
    _M.config = config
    _M.elements = elements
end

function _M.load_templates(cache_file)
    local f,err = io.open(cache_file, "r")
    if not f then
        print(err)
        return
    end
    templates = json.decode(f:read("*all"))
    if templates == nil then
        templates = {}
    end
    log.info('Loaded templates from file...')
    _M.templates = templates
    f:close()
end

function _M.save_templates(cache_file)
    local f,err = io.open(cache_file, "w")
    if not f then
        print(err)
        return
    end
    f:write(json.encode(_M.templates))
    f:close()
end

function _M.parse_value(raw,data_type)
    if type(type_map[data_type]) == 'function' then
        return type_map[data_type](raw)
    else
        return type_map.default(raw)
    end
end


function _M.parse_header(packet)
    local header = {
        ver   = u16(packet,1),
        len   = u16(packet,3),
        ts    = u32(packet,5),
        hrts  = os.date("%c", ts),
        seq   = u32(packet,9),
        domid = u32(packet,13),
    }
    return header, packet:sub(17)
end

function _M.parse_template_fields(set,data)
    local fields = {}
    -- For each field, pull type and length
    for i=1,set.no_fields do
        local typ = u16(data,1)
        local len = u16(data,3)
        local enterprise_id = nil
        if typ >= 32768 then -- If enterprise bit is set
            enterprise_id = u32(data,5)
            typ = typ - 32768
            data = data:sub(9)
        else
            data = data:sub(5)
        end

        local vars = _M.elements[typ] or {}

        local name
        if enterprise_id == 29305 then -- This is a reverse
            name = vars.name .. 'Reverse'
        else
            name = vars.name
        end

        local field = {
            typ = typ,
            name = name or 'Unknown',
            data_type = vars.data_type or 'unknown',
            data_semantic = vars.data_semantic or 'unknown',
            data_unit = vars.unit or 'unknown',
            enterprise_id = enterprise_id or 0,
            len = len,
        }
        fields[#fields+1] = field
    end
    return fields
end

function _M.parse_flows(template,data)
    local fields = template.fields
    local flows = {}
    -- While we still have data left
    while #data > 0 do
        -- Instantiate a new flow
        local flow = {}

        -- For our template fields, 
        for i=1,#fields do
            local field = {} 

            -- Lookup static values in metatable
            setmetatable(field, { __index = fields[i] })

            local field_len = field.len
            local data_type = field.data_type
            local raw_value = data:sub(1,field_len)
            local value = _M.parse_value(raw_value,data_type)
            field.raw_value = raw_value
            field.value = value
            flow[field.typ] = field
            data = data:sub(field_len+1)
        end
        flows[#flows+1] = flow
    end

    return flows
end

function _M.parse_set(packet)

    local header = packet:sub(1,4)
    local data   = packet:sub(5)

    local set = {
        id    = u16(header,1),
        len   = u16(header,3),
    }

    local set_data = data:sub(1,set.len-4)
    
    packet = packet:sub(set.len+1)

    if set.id == 2 then -- If this is a template set then parse as such
        set.tpl_id    = u16(set_data,1)
        set.no_fields = u16(set_data,3)

        local fields = {}
        
        set_data = set_data:sub(5)

        set.fields = _M.parse_template_fields(set,set_data)

        if not _M.templates then
            lp.dequeue("No templates identified, skipping...",5)
        else
            _M.templates[set.tpl_id] = set
        end

    elseif set.id == 3 then -- If this is an options template, ignore for the moment
        set.tpl_id          = u16(set_data,1)
        set.no_fields       = u16(set_data,3)
        set.no_scope_fields = u16(set_data,5)

        set_data = set_data:sub(7)

        -- Parse fields
        set.fields = _M.parse_template_fields(set,set_data)

        -- Scope fields always come first, set them to 'scope'
        for i=1,set.no_scope_fields do
            set.fields[i].scope = true
        end

        if not _M.templates then
            lp.dequeue("No templates identified, skipping...",5)
        else
            _M.templates[set.tpl_id] = set
        end

    elseif set.id >= 4 and set.id <= 255 then
        -- Ignore, these are not flow data sets
    else
        -- Template ID is our set.id
        if not _M.templates then
            lp.dequeue("No templates identified, skipping...",5)
        else
            local template = _M.templates[tostring(set.id)]
            if not template then
                lp.dequeue("Identified flow set with template ID " .. set.id .. " we don't have cached yet...",5)
            else
                set.flows = _M.parse_flows(template,set_data)
            end
        end
    end

    return set, packet
end

return _M
