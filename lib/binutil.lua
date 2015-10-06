local str_byte      = string.byte

local _M = {}

function _M.u8(b,o)
  o = o or 1
  return str_byte(b, o)
end

function _M.u16(b,o)
  local b1,b2
  o = o or 1
  b1, b2 = str_byte(b, o), str_byte(b, o+1)
  --        2^8     2^0
  return b1*256 + b2
end

function _M.u32(b,o)
  local b1,b2,b3,b4
  o = o or 1
  b1, b2 = str_byte(b, o), str_byte(b, o+1)
  b3, b4 = str_byte(b, o+2), str_byte(b, o+3)
  --        2^24          2^16       2^8     2^0
  return b1*16777216 + b2*65536 + b3*256 + b4
end

function _M.u64(b,o)
  local b1,b2,b3,b4,b5,b6,b7,b8
  o = o or 1
  b1, b2 = str_byte(b, o), str_byte(b, o+1)
  b3, b4 = str_byte(b, o+2), str_byte(b, o+3)
  b5, b6 = str_byte(b, o+4), str_byte(b, o+5)
  b7, b8 = str_byte(b, o+6), str_byte(b, o+7)
  return b1*(2^56) + b2*(2^48) + b3*(2^40) + b4*(2^32) + b5*16777216 + b6*65536 + b7*256 + b8
end

function _M.uvar(b,o)
    if #b == 1 then
        return _M.u8(b,o)
    elseif #b == 2 then
        return _M.u16(b,o)
    elseif #b == 4 then
        return _M.u32(b,o)
    elseif #b == 8 then
        return _M.u64(b,o)
    end
end

return _M
