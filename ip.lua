local bit_lshift   = bit.lshift
local bit_tobit    = bit.tobit
local bit_xor      = bit.bxor
local bit_band     = bit.band
local bit_bor      = bit.bor
local math_ceil    = math.ceil
local math_log     = math.log
local table_concat = table.concat
local table_insert = table.insert

local _M = { }

-- Pre-calculate masks
local bin_masks = {}
for i=1,32 do
    bin_masks[i] = bit_lshift(bit_tobit((2^i)-1), 32-i)
end

local bin_inverted_masks = {}
for i=1,32 do
    bin_inverted_masks[i] = bit_xor(bin_masks[i], bin_masks[32])
end

function _M.unsign(n)
    if n < 0 then
        n = 4294967296 + n
    end
    return n
end

function _M.num_to_octets(num)
    local octets = {}

    while num > 0 do
        local octet = num % 256
        num = num - octet
        num = num / 256
        table_insert(octets,1,octet)
    end
    return table_concat(octets,".")
end

function _M.integer_range_to_cidr(sub_lo,sub_hi)
    -- Get size of subnet
    local size = sub_hi - sub_lo

    start_ip = _M.num_to_octets(sub_lo)

    local slash

    if size == 0 then
        if sub_lo == 0 and sub_hi == 0 then
            start_ip = '0.0.0.0'
            slash = 0
        else
            slash = 32
        end
    else
        slash = (32 - math_ceil(math_log(size)/math_log(2)))
    end
    return start_ip .. '/' .. slash 
end

function _M.cidr_to_integer_range(cidr)
    local a, b, a1, a2, a3, a4, mask = cidr:find( '(%d+).(%d+).(%d+).(%d+)/(%d+)')
    if not a then 
        a, b, a1, a2, a3, a4 = cidr:find( '(%d+).(%d+).(%d+).(%d+)')
        mask = 32

        if not a then
            return nil
        end
    end

    local o1,o2,o3,o4, mask = tonumber( a1 ), tonumber( a2 ), tonumber( a3 ), tonumber( a4 ), tonumber( mask )
    if o1 < 0 or o1 > 255 or
        o2 < 0 or o2 > 255 or
        o3 < 0 or o3 > 255 or
        o4 < 0 or o4 > 255 or
        mask < 1 or mask > 32 then
        return nil
    end

    local ipno = o1*16777216 + o2*65536 + o3*256 + o4
    local lower = _M.unsign(bit_band(ipno,bin_masks[mask]))
    local upper = _M.unsign(bit_bor(lower,bin_inverted_masks[mask]))
    return lower, upper
end

return _M
