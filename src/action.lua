local _M = {}

local exit = ngx.exit
local say = ngx.say
local string_format = string.format
local string_char = string.char
local string_byte = string.byte


function _M.skip(waf, ctx, id, param)
    ctx.id = id
    ctx.enable = false

    return true
end


function _M.allow(waf, ctx, id, param)
    ctx.id = id
    ctx.enable = false

    return false
end


function _M.deny(waf, ctx, id, param)
    ctx.id = id
    ctx.enable = true
    ngx.status = 403

    if waf.html[param] ~= nil then
        say(waf.html[param])
    else
        say(waf.html['default'])
    end

    return true
end


return _M
