local _M = {}

local exit = ngx.exit
local say = ngx.say
local string_format = string.format
local string_char = string.char
local string_byte = string.byte
local ngx_re_sub = ngx.re.sub


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


function _M.log(waf, ctx, id, param)
    ctx.id = id
    ctx.enable = true

    return true
end


function _M.deny(waf, ctx, id, param)
    ctx.id = id
    ctx.enable = true

    if waf.dry == true then
        return true
    end

    ngx.status = 403

    local html = nil

    if waf.html[param] ~= nil then
        html = waf.html[param]
    else
        html = waf.html['default']
    end

    if html == nil then
        html = ''
    end

    html = ngx_re_sub(html, '<!--id-->', id)
    if html == nil then
        html = "<h1>You Have Been Block</h1>"
    end

    say(html)

    return true
end


return _M
