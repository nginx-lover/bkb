local _M = {
    _VERSION = "0.1.0"
}

local get_headers = ngx.req.get_headers
local operator = require("bkb.operator")
local action = require("bkb.action")
local transform = require("bkb.transform")
local config_pcre = require("bkb.config.pcre")
local config_file = require("bkb.config.file")
local config_html = require("bkb.config.html")
local config_whitelistip = require("bkb.config.whitelistip")
local iputils = require("bkb.lib.resty.iputils")
local ip_in_cidrs = iputils.ip_in_cidrs
local loadstring = loadstring
local util = require("bkb.util")
local time = require("bkb.lib.time")
local gettimeofday = time.gettimeofday
local ngx_log = ngx.log
local ERR = ngx.ERR
local get_phase = ngx.get_phase

local wafrule = ngx.shared.wafrule

_M.dry = false
_M.appname = "WAF-BKB"
_M.operator = operator
_M.action = action
_M.transform = transform
_M.util = util
_M.pcre = config_pcre
_M.file = config_file
_M.html = config_html
_M.use_x_forwarded_for = false
_M.whitelistip = iputils.parse_cidrs(config_whitelistip)


function _M.run()
    -- run or disable
    local run = wafrule:get("run")

    if run == false then
        return
    end

    -- dry run mode or not
    local dry = wafrule:get("dry")

    if dry == true then
        _M.dry = true
    else
        _M.dry = false
    end

    local phase = get_phase()
    local begin = gettimeofday()
    local ctx = ngx.ctx
    ctx._cache = {}
    ctx.TX = {}
    ctx.dynamic = {}
    ctx.delay = 0

    -- update ip on the fly
    local ip = require("bkb.ip")
    local version, flags = wafrule:get("ip.version")
    if version ~= nil then
        if version ~= ip._VERSION then
            local code, flags = wafrule:get("ip")
            if code == nil then
                ngx_log(ERR, "[WAF] get ip nil")
            else
                local rip, err = loadstring(code)
                if rip == nil then
                    ngx_log(ERR, "[WAF] loadstring get err" .. err)
                    return ngx.exit(500)
                else
                    -- update code on the fly
                    package.loaded.ip = rip()
                end
            end
        end
    end

    -- update rule on the fly
    local rule = require("bkb.rule")
    local version, flags = wafrule:get("rule.version")
    if version ~= nil then
        if version ~= rule._VERSION then
            local code, flags = wafrule:get("rule")
            if code == nil then
                ngx_log(ERR, "[WAF] get rule nil")
            else
                local rcode, err = loadstring(code)
                if rcode == nil then
                    ngx_log(ERR, "[WAF] loadstring get err" .. err)
                    return ngx.exit(500)
                else
                    -- update code on the fly
                    package.loaded.rule = rcode()
                end
            end
        end
    end

    -- skip whitelistip forever
    local remote_addr = ngx.var.remote_addr;
    if _M.use_x_forwarded_for then
        remote_addr = get_headers()["x-forwarded-for"] or ngx.var.remote_addr
    end

    if ip_in_cidrs(remote_addr, _M.whitelistip) then
        return
    end

    if phase == "access" then
        if ip.run(_M, ctx) == false then
           rule.run(_M, ctx)
        end
    else
        rule.run(_M, ctx)
    end

    local delay = gettimeofday() - begin
    ctx.delay = delay
    ngx.req.set_header(_M.appname, delay)
end

return _M
