
-- #############################
-- # Provides Eventing Actions #
-- #############################

local util         = require('util')
local os_date      = require("os").date
local curl_request = require("http.client").request
local log_error    = require("log").error
local json_encode  = require("json").encode
local table_concat = require("table").concat
local fiber_time   = require("fiber").time

local _M = { config = {} }
_M.set_config = function(config)
    _M.config = config
end


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
_M.trigger = function(event,delay,attributes)
    local now          = os.date("!%a, %d %b %Y %X GMT",fiber_time())
    local events      = _M.config.events
    for event_name, event_settings in pairs(events) do
        local events = event_settings.events

        local event_specific_settings = events[event]
        
        -- If this event matches the list of events to trigger on

        if event_specific_settings and (event_specific_settings.delay <= delay or type(event_specific_settings) == 'boolean') then
            local actions = event_settings.actions

            -- For each action
            for action_name, action_settings in pairs(actions) do

                local action_message  = action_settings.message
                local action_color    = action_settings.color
                local action_endpoint = action_settings.endpoint
            
                -- If action name is hipchat
                if action_name == 'hipchat' then
                    -- Build up notification message 
                    attributes.event_name = event:upper()
                    local message = action_message % attributes

                    -- Build up notification body
                    local notify_body = {
                       color   = action_color,
                       message = message,
                       notify  = action_endpoint.notify or false,
                       message_format = action_endpoint.message_format or 'html',
                    }

                    local headers = {}

                    headers['content-type'] = 'application/json'

                    local json_body = json_encode(notify_body)

                    -- Submit request to Hipchat
                    local res = curl_request('POST',action_endpoint.url,json_body,{headers = headers})

                    if res.status ~= 204 then
                        log_error("Unable to submit notification with following body due to status %(status):\n: %(notify_body)" % {
                            status = res.status,
                            notify_body = json_body
                        })
                    end
                end
                return true
            end
        end
    end
    return false
end

return _M
