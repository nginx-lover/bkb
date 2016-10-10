local getenv = os.getenv
local wafdir = getenv('WAF-DIR')
local loadstring = loadstring


local wafrule = ngx.shared.wafrule
local f, err = io.open (wafdir .. "/ip.lua", "r")
if err ~= nil then
    ngx.say("open file get error" .. err)
    ngx.exit(500)
    return
end

local code = f:read("*all")
f:close()

local rcode, err = loadstring(code)
if rcode == nil then
    ngx.say("loadstring get err" .. err)
    return ngx.exit(500)
end
local ip = rcode()

local success, err, forcible = wafrule:set("ip.version", ip._VERSION)
if success == false then
    ngx.say("set ipversion error " .. err)
    return ngx.exit(500)
end

local success, err, forcible = wafrule:set("ip", code)
if success == false then
    ngx.say("set ip code error " .. err)
    return ngx.exit(500)
end

ngx.say("update ip success")
