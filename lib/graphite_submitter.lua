local fiber      = require("fiber")
local table      = require("table")
local tbl_concat = table.concat
local log        = require("log")
local log_info   = log.info
local log_error  = log.error
local socket     = require("socket")
local ipfix      = require("ipfix")

local _M = { config = {} }

_M.set_config = function(config)
    _M.config = config
end

local graphite_submitter = function(graphite_channel)
    local self = fiber.self()
    self:name("ipfix/graphite-submitter")

    local pending = 0
    local output = ''
    local conn_info = socket.getaddrinfo(_M.config.graphite_host,'2010')
    local graphite_host = conn_info[1].host
    local graphite_port = _M.config.graphite_port

    if not graphite_host or not graphite_port then
        log_info('Disabling graphite submission, no host or port configured!')
        return
    else
        log_info("Resolved graphite host to " .. graphite_host .. ":" .. graphite_port)
    end

    local graphite = socket("AF_INET", "SOCK_DGRAM", "udp")

    while 1 == 1 do
        local to_submit = graphite_channel:get(1.0)
        if to_submit ~= nil then
            pending = pending + 1
            output = output .. tbl_concat(to_submit," ") .. "\n"
        end

        if pending >= 5 or to_submit == nil then
            local sent = graphite:sendto(graphite_host,graphite_port,output)
            if not sent then
                log_error("Metric output to Graphite at " .. graphite_host .. ":" .. graphite_port .. " failed! - " .. graphite:error())
            end
            pending = 0
            output  = ""
            fiber.sleep(0.001)
        end
    end
    graphite:close()
end

_M.start = function(graphite_channel)
    return fiber.create(graphite_submitter,graphite_channel)
end

return _M
