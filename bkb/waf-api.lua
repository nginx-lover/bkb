-- @Author: detailyang
-- @Date:   2016-10-10 14:07:32
-- @Last Modified by:   detailyang
-- @Last Modified time: 2016-10-13 19:46:54
local _M = {}

local ngx_re_match = ngx.re.match
local method = ngx.req.get_method()
local cjson = require("cjson.safe")
local cjson_encode = cjson.encode
local cjson_decode = cjson.decode
local getenv = os.getenv
local wafdir = getenv('WAF-DIR')
local loadstring = loadstring
local wafrule = ngx.shared.wafrule
local waf_mode_file = nil


local function do_rule()
    local f, err = io.open (wafdir .. "/rule.lua", "r")
    if err ~= nil then
        ngx.say("open file get error " .. err)
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
    local rule = rcode()

    local success, err, forcible = wafrule:set("rule.version", rule._VERSION)
    if success == false then
        ngx.say("set rule version error " .. err)
        return ngx.exit(500)
    end

    local success, err, forcible = wafrule:set("rule", code)
    if success == false then
        ngx.say("set rule code error " .. err)
        return ngx.exit(500)
    end

    ngx.say("update rule success")
end


local function do_ip()
    local f, err = io.open (wafdir .. "/ip.lua", "r")
    if err ~= nil then
        ngx.say("open file get error " .. err)
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
end


local function do_waf_get()
    local dry = wafrule:get("dry")
    local run = wafrule:get("run")
    local ip_version = wafrule:get("ip.version")
    local rule_version = wafrule:get("rule.version")
    local totaldelay = wafrule:get("totaldelay") or 0
    local maxdelay = wafrule:get("maxdelay") or 0
    local totalcnt = wafrule:get("totalcnt") or 1
    local trigger = wafrule:get("trigger") or 0

    local rv = {
        waf_mode_file = waf_mode_file,
        run = run,
        dry = dry,
        ip = {
            version = ip_version,
        },
        rule = {
            version = ip_version,
        },
        totaldelay = totaldelay,
        totalcnt = totalcnt,
        delay = totaldelay / totalcnt,
        trigger = trigger,
        maxdelay = maxdelay,
    }

    return ngx.say(cjson_encode(rv))
end


local function do_waf_post()
    ngx.req.read_body()  -- explicitly read the req body
    local data = ngx.req.get_post_args()

    --[[
    carefully, it's blocking IO
    --]]
    local f = nil
    if waf_mode_file ~= nil then
        f = io.open(waf_mode_file, "w+")

        if f == nil then
            ngx.say("waf mode file open err ", waf_mode_file)
        end
    end

    local dry = data['dry']
    if dry then
        if dry == '0' then
            dry = false
        elseif dry == '1' then
            dry = true
        else
            ngx.say("set waf dry mode unknow value ", dry)
            return ngx.exit(500)
        end

        ngx.say("set waf dry mode: ", dry)

        local success, err, forcible = wafrule:set("dry", dry)
        if success == false then
            ngx.say("set waf dry mode error " .. err)
            return ngx.exit(500)
        end
    end

    local run = data['run']
    if run then
        if run == '0' then
            run = false
        elseif run == '1' then
            run = true
        else
            ngx.say("set waf run mode unknow value ", run)
            return ngx.exit(500)
        end

        ngx.say("set waf run mode: ", run)

        local success, err, forcible = wafrule:set("run", run)
        if success == false then
            ngx.say("set waf run mode error " .. err)
            return ngx.exit(500)
        end
    end

    if f ~= nil then
        local mdry = wafrule:get("dry")
        local mrun = wafrule:get("run")
        local mode = {
            dry = mdry,
            run = mrun,
        }

        if dry ~= nil then
            mode["dry"] = dry
        end

        if run ~= nil then
            mode["run"] = run
        end

        mode = cjson_encode(mode)

        local _, err = f:write(mode)
        if err ~= nil then
            ngx.say("sync waf to file: ",  waf_mode_file, " err", err)
            ngx.exit(500)
        else
            ngx.say("sync waf to file: ", waf_mode_file, " success")
        end

        f:close()
    end
end


local function do_waf()
    if method == 'GET' then
        do_waf_get()
    elseif method == 'POST' then
        do_waf_post()
    else
        return ngx.say("only support GET|POST method")
    end
end


local dispatch = {
    ["/waf"] = do_waf,
    ["/ip"] = do_ip,
    ["/rule"] = do_rule
}


function _M.run(_waf_mode_file)
    local uri = ngx.var.uri

    if waf_mode_file == nil then
        waf_mode_file = _waf_mode_file
    end

    if dispatch[uri] ~= nil then
        dispatch[uri]()
    else
        ngx.say("cannot found the uri ", uri)
        return ngx.exit(404)
    end
end




return _M
