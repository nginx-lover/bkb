local _M = {}
local logger = require("bkb.lib.resty.logger.socket")
local logger_log = logger.log
local rfc5424 = require("bkb.lib.rfc5424")
local cjson = require("cjson")
local cjson_encode = cjson.encode
local waf = require("bkb.waf")
local config_rsyslog = require("bkb.config.rsyslog")
local util = require("bkb.util")
local dict_add = util.dict_add
local appname = waf.appname
local wafrule = ngx.shared.wafrule
local rfc5424_encode = rfc5424.encode
local hostname = ngx.var.hostname
local pid = ngx.worker.pid()
local raw_header = ngx.req.raw_header
local get_headers = ngx.req.get_headers
local ngx_log = ngx.log
local ERR = ngx.ERR

function _M.run()
    local delay = ngx.ctx.delay
    local newval, err = dict_add(wafrule, "totalcnt", 1, 0)
    if err ~= nil then
        ngx_log(ERR, "failed to incr key[totalcnt] ", err)
    end

    if type(delay) == 'number' then
        newval, err = dict_add(wafrule, "totaldelay", delay, 0)
        if err ~= nil then
            ngx_log(ERR, "failed to incr key[totaldelay] ", err)
        end

        local maxdelay = wafrule:get("maxdelay") or 0
        if delay > maxdelay then
            local success, err, forcible = wafrule:set("maxdelay", delay)
            if success == false then
                ngx_log(ERR, "failed to set key[maxdelay] ", err)
            end
        end
    end

    if not logger.initted() then
        local ok, err = logger.init(config_rsyslog)
        if not ok then
            ngx_log(ERR, "failed to initialize the logger: ", err)
            return
        end
    end

    if ngx.ctx.enable == true then
        newval, err = dict_add(wafrule, "trigger", 1, 0)
        if err ~= nil then
            ngx_log(ERR, "failed to incr key[trigger] ", err)
        end

        local remote_addr = ngx.var.remote_addr;
        if waf.use_x_forwarded_for then
            remote_addr = get_headers()['x-forwarded-for'] or ngx.var.remote_addr
        end

        local msg = {
            id = ngx.ctx.id,
            delay = ngx.ctx.delay,
            remote_addr = remote_addr,
            head = raw_header(),
            body = ngx.ctx.body,
        }
        local jmsg = cjson_encode(msg)
        local rfc5424_msg = rfc5424_encode(config_rsyslog.facility, config_rsyslog.severity, hostname, pid, appname, jmsg)
        local _, err = logger_log(rfc5424_msg)
        if err then
            ngx_log(ERR, "failed to log message: ", err)
            return
        end
    end
end

return _M
