-- @Author: detailyang
-- @Date:   2016-10-13 16:01:27
-- @Last Modified by:   detailyang
-- @Last Modified time: 2016-10-13 17:31:37
local _M = {}
local cjson = require("cjson.safe")
local cjson_encode = cjson.encode
local cjson_decode = cjson.decode
local wafrule = ngx.shared.wafrule
local reload = wafrule:get("reload")
local ngx_log = ngx.log
local ngx_ERR = ngx.ERR
local ngx_ALERT = ngx.ALERT

-- markup reload
wafrule:set("reload", 1)

function _M.run(waf_mode_file)

    if reload == nil then
        -- startup
        if waf_mode_file == nil then
            -- no fs storage
        else
            local mode = {}
            local f = io.open(waf_mode_file, "r")
            if f == nil then
                ngx_log(ngx_ERR, "waf mode file open err ", waf_mode_file)
            else
                -- carefully, it's blocking IO
                local jmode = f:read("*a")
                mode = cjson_decode(jmode) or {}
            end

            --[[
            default dry is true and run is false
            --]]
            local dry = true
            local run = true

            if mode["dry"] == false then
                dry = false
            end

            if mode["run"] == false then
                run = false
            end

            local success, err, forcible = wafrule:set("dry", dry)
            if success == false then
                ngx_log(ngx_ERR, "set waf dry mode error " .. err)
            end

            success, err, forcible = wafrule:set("run", run)
            if success == false then
                ngx_log(ngx_ERR, "set waf run mode error " .. err)
            end
            ngx_log(ngx_ALERT, "set waf run mode: ", run)
            ngx_log(ngx_ALERT, "set waf dry mode: ", dry)
        end
    else
        -- reload
    end
end


return _M
