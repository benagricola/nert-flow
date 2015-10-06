local fiber      = require("fiber")
local table      = require("table")
local tbl_concat = table.concat
local math       = require("math")
local math_ceil  = math.ceil
local socket     = require("socket")
local ipfix      = require("ipfix")

local _M = { config = {} }

_M.set_config = function(config)
    _M.config = config
end

local stat_generator = function(graphite_channel)
    local self = fiber.self()
    self:name("ipfix/stat-generator")

    while 1 == 1 do
        local now = math_ceil(fiber.time())

        -- Submit size of each box to graphite
        for k, v in box.space._space:pairs() do
            local space_name = v[3]
            if box.space[space_name].index[0] ~= nil then
                tuple_count = box.space[space_name].index[0]:count()
            else
                tuple_count = 0
            end

            graphite_channel:put({"flow.stats.space."..space_name..".tuple_count",math_ceil(tuple_count),now})
        end

        for field, value in pairs(box.slab.info()) do
            if type(value) == "number" then
                graphite_channel:put({"flow.stats.box.slab."..field,math_ceil(value),now})

            else
                if field == "slabs" then
                    -- Submit each slab size plus item count and used
                    for _, slabvar in ipairs(value) do
                        local stat_path = "flow.stats.box.slab.slabs."..tostring(slabvar.item_size)
                        graphite_channel:put({stat_path .. ".count",slabvar.item_count,now})
                        graphite_channel:put({stat_path .. ".mem_free",slabvar.mem_free,now})
                        graphite_channel:put({stat_path .. ".mem_used",slabvar.mem_used,now})
                        graphite_channel:put({stat_path .. ".slab_count",slabvar.slab_count,now})
                        graphite_channel:put({stat_path .. ".slab_size",slabvar.slab_size,now})
                    end
                end
            end
        end
        for field, value in pairs(box.stat()) do
            if type(value) == "table" then
                local field = field:lower()
                if value.total then
                    graphite_channel:put({"flow.stats.box.stat."..field..".total",math_ceil(value.total),now})
                end
                if value.rps then
                    graphite_channel:put({"flow.stats.box.stat."..field..".rps",math_ceil(value.rps),now})
                end
            end
        end
        fiber.sleep(10)
    end
end

_M.start = function(graphite_channel)
    return fiber.create(stat_generator,graphite_channel)
end

return _M
