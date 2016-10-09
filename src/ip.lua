local _M = {
    _VERSION = 1475139616
}
local ngx_time = ngx.time
local t = {}
local waf =  require('waf')
local get_headers = ngx.req.get_headers


-----------------------------------
--------------action---------------
-----------------------------------
local waf_action_skip = waf.action.skip
local waf_action_deny = waf.action.deny
local waf_action_allow = waf.action.allow
local waf_action_log = waf.action.log


-----------------------------------
--------------operator-------------
-----------------------------------
local waf_operator_eq = waf.operator.eq


function _M.run(waf, ctx)
    -----------------------------------
    --------------variable-------------
    -----------------------------------
    local waf_variable_ip = ngx.var.remote_addr
    if waf.use_x_forwarded_for then
        waf_variable_ip = get_headers()['x-forwarded-for'] or ngx.var.remote_addr
    end
    local waf_variable_uri = ngx.var.uri
    local waf_variable_host = ngx.var.host


    local elapsed = ngx_time()

    -- blacklist
    if elapsed <= 1506675534 then
        if waf_variable_ip == [==[223.240.53.221]==] then
            return waf_action_deny(waf, ctx, '-2', [==[null]==])
        end
    end
    --whitelist
    return false
end

return _M
