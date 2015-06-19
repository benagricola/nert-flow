local os = require("os")
local _M = { messages = {} }

function _M.dequeue(message,interval)
    if not _M.messages[message] then
        _M.messages[message] = os.time()
        print(message)
    else
        if os.time() > _M.messages[message] + interval then
            _M.messages[message] = nil
            print(message)
        end
    end
end

return _M
