local _M = {}
local logger = require("lib.resty.logger.socket")
local logger_log = logger.log
local rfc5424 = require("lib.rfc5424")
local cjson = require("cjson")
local cjson_encode = cjson.encode
local waf = require("waf")
local config_rsyslog = require("config.rsyslog")
local appname = waf.appname
local rfc5424_encode = rfc5424.encode
local hostname = ngx.var.hostname
local pid = ngx.worker.pid()
local raw_header = ngx.req.raw_header
local get_headers = ngx.req.get_headers
local ngx_log = ngx.log
local ERR = ngx.ERR

function _M.run()
    if not logger.initted() then
        local ok, err = logger.init(config_rsyslog)
        if not ok then
            ngx_log(ERR, "failed to initialize the logger: ", err)
            return
        end
    end

    if ngx.ctx.enable == true then
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
        local rfc5424_msg = rfc5424_encode('LOCAL6', 'INFO', hostname, pid, appname, jmsg)
        local _, err = logger_log(rfc5424_msg)
        if err then
            ngx_log(ERR, "failed to log message: ", err)
            return
        end
    end
end

return _M
