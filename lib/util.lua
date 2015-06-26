local digest       = require('digest')
local digest_crc32 = digest.crc32
local string       = require('string')
local str_gsub     = string.gsub
local table        = require('table')
local table_concat = table.concat
local _M = {}

-- Adds a string interpolation method using the mod sign (string % {replacements})
_M.interp = function(s, tab)
    return (str_gsub(s,'%%%(([%w_-]+)%)', function(w)
        return tab[w] or w
    end))
end
getmetatable('').__mod = _M.interp


_M.aspath_hash = function(path)
    if type(path) ~= 'table' or #path < 1 then
        return nil
    end
    return digest_crc32(table_concat(path," "))
end

_M.route2table = function(route)
    if route == nil then
        return nil
    end
    return {
        start_ip             = route[1],
        end_ip               = route[2],
        neighbor             = route[3],
        as_path              = route[4],
        origin_as            = route[5],
        communities          = route[6],
        options              = route[7],
    }
end

_M.neighbor2table = function(neighbor)
    if neighbor == nil then
        return nil
    end
    return {
        peer_ip = neighbor[1],
        routes  = neighbor[2],
    }
end

_M.aspath2table = function(aspath)
    if aspath == nil then
        return nil
    end
    return {
        hash = aspath[1],
        path = aspath[2],
    }
end

_M.origin2table = function(origin)
    if origin == nil then
        return nil
    end
    return {
        asn      = origin[1],
        start_ip = origin[2],
        end_ip   = origin[3],
    }
end

_M.trigger_log2table = function(trigger_log)
    if trigger_log == nil then
        return nil
    end
    return {
        timestamp    = trigger_log[1],
        trigger_name = trigger_log[2],
        arguments    = trigger_log[3],
    }
end

_M.token2table = function(token)
    if token == nil then
        return nil
    end

    return {
        private_token = token[1],
        public_token  = token[2],
        permissions   = token[3],
    }
end

_M.get_aspath = function(path_hash)
    local spc_paths = box.space.paths
    local as_path = spc_paths:get{tonumber(path_hash)}

    if as_path == nil then
        return nil
    end

    return as_path[2]
end

return _M
