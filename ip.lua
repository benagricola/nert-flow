local bit_lshift = bit.lshift
local bit_tobit = bit.tobit
local bit_xor = bit.bxor

local _M = { }

-- Pre-calculate masks
local bin_masks = {}
for i=1,32 do
    bin_masks[tostring(i)] = bit_lshift(bit_tobit((2^i)-1), 32-i)
end

local bin_inverted_masks = {}
for i=1,32 do
local i = tostring(i)
    bin_inverted_masks[i] = bit_xor(bin_masks[i], bin_masks["32"])
end

function _M.cidr_to_integer_range(cidr)
    local a, b, a1, a2, a3, a4, mask = cidr:find( '(%d+).(%d+).(%d+).(%d+)/(%d+)')
    if not a then 
        return nil 
    end

    local o1,o2,o3,o4 = tonumber( a1 ), tonumber( a2 ), tonumber( a3 ), tonumber( a4 )
    local ipno = o1*16777216 + o2*65536 + o3*256 + o4
    local range = {}
    local lower = bit.band(ipno,bin_masks[mask])
    local upper = bit.bor(lower,bin_inverted_masks[mask])
    range[1] = lower
    range[2] = upper
    range[3] = cidr
    return range
end

return _M
