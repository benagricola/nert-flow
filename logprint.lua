local log = require("log")
local fiber = require("fiber")
local _M = { messages = {} }

function _M.dequeue(message,interval)
    if not _M.messages[message] then
        _M.messages[message] = fiber.time()
        log.info(message)
    else
        if fiber.time() > _M.messages[message] + interval then
            _M.messages[message] = nil
            log.info(message)
        end
    end
end

return _M
