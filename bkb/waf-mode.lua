-- @Author: detailyang
-- @Date:   2016-10-10 14:07:32
-- @Last Modified by:   detailyang
-- @Last Modified time: 2016-10-10 14:36:12

local wafrule = ngx.shared.wafrule
local method = ngx.req.get_method()
local cjson = require("cjson.safe")
local cjson_encode = cjson.encode


local function do_get()
    local dry = wafrule:get("dry")
    local run = wafrule:get("run")
    local ip_version = wafrule:get("ip.version")
    local rule_version = wafrule:get("rule.version")
    local ip = wafrule:get("ip")
    local rule = wafrule:get("rule")

    local rv = {
        run = run,
        dry = dry,
        ip = {
            version = ip_version,
            code = ip,
        },
        rule = {
            version = ip_version,
            code = rule,
        }
    }

    return ngx.say(cjson_encode(rv))
end

local function do_post()
    ngx.req.read_body()  -- explicitly read the req body
    local data = ngx.req.get_post_args()

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
end


if method == 'GET' then
    do_get()
elseif method == 'POST' then
    do_post()
else
    return ngx.say("only support GET|POST method")
end

