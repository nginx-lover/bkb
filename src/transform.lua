local _M = {}

local gsub = ngx.re.gsub
local match = ngx.re.match
local unescape_uri = ngx.unescape_uri
local base64_decode = ngx.base64_decode
local base64_encode = ngx.base64_encode
local string_char = string.char
local string_lower = string.lower


function _M.length(waf, value)
    if value == nil then
        return 0
    end

    if type(value) == 'string' then
        return #value
    end

    return 0
end


function _M.cmdLine(waf, value)
    return value
end


function _M.normalise_path(waf, value)
    while (match(value, [=[[^/][^/]*/\.\./|/\./|/{2,}]=], waf.pcre.options)) do
        value = gsub(value, [=[[^/][^/]*/\.\./|/\./|/{2,}]=], '/', waf.pcre.options)
    end

    return value
end


function _M.normalisePathWin(waf, value)
    value = value:gsub('\\', '/')
    while (match(value, [=[[^/][^/]*/\.\./|/\./|/{2,}]=], waf.pcre.options)) do
        value = gsub(value, [=[[^/][^/]*/\.\./|/\./|/{2,}]=], '/', waf.pcre.options)
    end

    return value
end


function _M.none(waf, value)
    return value
end


function _M.sha1(waf, value)
    return ngx.sha1_bin(value)
end


function _M.htmlEntityDecode(waf, value)
    local str = gsub(value, [=[&lt;]=], '<', waf.pcre.options)

    str = gsub(str, [=[&gt;]=], '>', waf.pcre.options)
    str = gsub(str, [=[&quot;]=], '"', waf.pcre.options)
    str = gsub(str, [=[&apos;]=], "'", waf.pcre.options)
    str = gsub(str, [=[&#(\d+);]=], function(n) return string_char(n[1]) end, waf.pcre.options)
    str = gsub(str, [=[&#x(\d+);]=],
        function(n) return string_char(tonumber(n[1], 16)) end, waf.pcre.options)
    str = gsub(str, [=[&amp;]=], '&', waf.pcre.options)

    return str
end


function _M.compressWhitespace(waf, value)
    return gsub(value, [=[\s+]=], ' ', waf.pcre.options)
end


function _M.urlDecodeUni(waf, value)
    return unescape_uri(value)
end


function _M.jsDecode(waf, value)
    return value
end


function _M.cssDecode(waf, value)
    return value
end


function _M.lowercase(waf, value)
    return string_lower(value)
end


function _M.removeNulls(waf, value)
    return value
end


function _M.removeWhitespace(waf, value)
    return gsub(value, [=[\s+]=], '', waf.pcre.options)
end


function _M.replaceComments(waf, value)
    return gsub(value, [=[\/\*(\*(?!\/)|[^\*])*\*\/]=], '', waf.pcre.options)
end


function _M.base64Decode(waf, value)
    return base64_decode(value)
end


function _M.base64Encode(waf, value)
    return base64_encode(value)
end


return _M
