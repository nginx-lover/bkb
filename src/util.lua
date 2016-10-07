local _M = {}


local match = ngx.re.match
local resty_cookie = require("lib.resty.cookie")
local xml = require("lib.xml")
local xml_parse = xml.parse
local string_sub = string.sub
local string_lower = string.lower
local cjson = require "cjson"
local json = require("cjson.safe")
local json_decode = json.decode
local cjson_decode = cjson.decode
local upload = require("lib.resty.upload")


function _M.implode(t, delimiter)
    local len = _M.count_table(t)
    if len == 0 then
        return ""
    end

    local string = t[1]
    for i = 2, len do
        string = string .. delimiter .. t[i]
    end

    return string
end


function _M.build_query(t)
    local len = _M.count_table(t)
    if len == 0 then
        return ""
    end

    local str = ""
    for k, v in pairs(t) do
        str = k .. '=' ..v .. '&'
    end

    return str
end


function _M.get_request_protocol(request_line)
    for i=#request_line, 0, -1 do
        local c = request_line:sub(i, i)
        if (c == ' ') then
            return request_line:sub(i+1, #request_line)
        end
    end

    return request_line
end


function _M.count_field_from_table(waf, t)
    if type(t) == 'string' then
        if #t > 0 then
            return 1
        else
            return 0
        end
    end
    if type(t) == 'number' then
        return t
    end
    local count = 0
    for _, _ in pairs(t) do
        count = count + 1
    end

    return count
end


function _M.get_first_line(str)
    local index = string.find(str, "\r\n")
    if index ~= nil then
        return string_sub(str, 0, index - 1)
    else
        return str
    end
end

function _M.get_field_from_table(waf, t, field, type, reverse)
    local nt = {}

    if type == 'rx' then
        if reverse == false then
            for k, v in pairs(t) do
                if match(k, field, waf.pcre.options) then
                    nt[k] = v
                end
            end
        else
            for k, v in pairs(t) do
                if not match(k, field, waf.pcre.options) then
                        nt[k] = v
                end
            end
        end
    elseif type == 'eq' then
        return t[field]
    elseif type == 'beginsWith' then
        -- TODO
    end

    return nt
end


function _M.get_cookies()
    local cookies = resty_cookie:new()
    local fields, err = cookies:get_all()

    if not fields then
        return {}
    end

    return fields
end


function _M.get_table_value(t)
    if (t == nil) then return {} end

    local values = {}
    for k, v in pairs(t) do
        values[#values + 1] = v
    end

    return values
end


function _M.get_table_names(t)
    if (t == nil ) then return {} end

    local names = {}
    for k, v in pairs(t) do
        names[#names + 1] = k
    end

    return names
end


function _M.merge_table(a, b)
    local c = {}
    for k, v in pairs(a) do
        c[k] = v
    end

    for k, v in pairs(b) do
        c[k] = v
    end

    return c
end


function _M.merge_tables(...)
    local t = {}
    local arg
    for i=1, select('#', ...) do
        arg = select(i,...)
        if type(arg) == 'table' then
            for k, v in pairs(arg) do
                t[k] = v
            end
        elseif type(arg) == 'string' then
            table.insert(t, arg)
        elseif type(arg) == 'number' then
            return arg
        end

    end

    return t
end


function _M.count_table(t)
    local count = 0
    for _ in pairs(t) do
        count = count + 1
    end

    return count
end


function _M.split(str, pat)
    local t = {}
    local fpat = "(.-)" .. pat
    local last_end = 1
    local s, e, cap = str:find(fpat, 1)

    while s do
        if s ~= 1 or cap ~= "" then
            table.insert(t,cap)
        end
        last_end = e+1
        s, e, cap = str:find(fpat, last_end)
    end

    if last_end <= #str then
        cap = str:sub(last_end)
        table.insert(t, cap)
    end

    return t
end


function _M.count_table_value_length(t)
    local count = 0
    for k, v in pairs(t) do
        if type(v) == 'string' then
            count = count + #v
        end
    end

    return count
end


function _M.remove_boolean_and_table(variable)
    if type(variable) == 'boolean' then
        return ''
    elseif type(variable) == 'table' then
        local t = {}
        for k, v in pairs(variable) do
            if type(v) == 'boolean' then
                t[k] = ''
            elseif type(v) == 'table' then
                for sk, sv in pairs(v) do
                    if type(sv) == 'boolean' then
                        t[k.. sk] = ''
                    else
                        t[k.. sk] = sv
                    end
                end
            else
                t[k] = v
            end
        end

        return t
    end

    return variable
end


--
-- TODO: support stream regular match
--
function _M.get_post_args()
    local headers = ngx.req.get_headers()
    local content_type = headers["content-type"]
    local method = ngx.var.request_method

    if "GET" == method then
        return {}
    end

    ngx.req.read_body()
    if content_type ~= nil and string_sub(content_type, 1, 20) == "multipart/form-data;" then
        local data = ngx.req.get_body_data() -- ngx.req.get_post_args()
        if not data then
            local datafile = ngx.req.get_body_file()
            if datafile then
                local fh, err = io.open(datafile, "r")
                if fh then
                    fh:seek("set")
                    -- THIS is blocking io, so be careful
                    data = fh:read("*a")
                    fh:close()
                end
            end
        end
        if not data then
            return {}
        end

        local boundary = "--" .. string.sub(content_type ,31)
        local bt = _M.split(data, boundary)
        local last = table.remove(bt)

        local args = {}
        local filename = {}
        for k, v in ipairs(bt) do
            local sp, ep, namecap, filenamecap = string.find(v,'Content%-Disposition: form%-data; name="(.+)"; filename="(.*)"')
            if not sp then
                local t = _M.split(v, "\r\n\r\n")
                if (#t == 2) then
                    local name = string.sub(t[1], #"\r\nContent-Disposition: form-data; name=\"" + 1, -2)
                    if #name == 0 then
                        return args
                    end

                    local value = t[2]
                    if #value > 2 and string_sub(value, #value-1, #value) == '\r\n' then
                        args[name] = string_sub(value, 1, #value-2)
                    else
                        args[name] = value
                    end
                end
            else
                args[namecap] = filenamecap
                filename[#filename] = filenamecap
            end
        end

        return args, filename
    else
        local post_args = ngx.req.get_post_args()

        if content_type ~= nil and string_sub(content_type, 1, 33) == 'application/x-www-form-urlencoded' then

            return post_args

        elseif content_type ~= nil and string_sub(content_type, 1, 8) == 'text/xml' then
            for k, v in pairs(post_args) do
                return xml_parse(k)
            end

            return {}

        elseif content_type ~= nil and string_sub(content_type, 1, 16) == 'application/json' then
            local t = {}
            for k, v in pairs(post_args) do
                local lv = json_decode(k)
                -- only support 5 nested json to plain table
                if type(lv) == 'number' then
                    t[0] = k
                    return t
                elseif type(lv) == 'table' then
                    for k1, v1 in pairs(lv) do
                        if type(v1) == 'number' or type(v1) == 'string' then
                            t[k1] = v1
                        elseif type(v1) == 'table' then
                            for k2, v2 in pairs(v1) do
                                if type(v2) == 'number' or type(v2) == 'string' then
                                    t[k2] = v2
                                elseif type(v2) == 'table' then
                                    for k3, v3 in pairs(v2) do
                                        if type(v3) == 'number' or type(v3) == 'string' then
                                            t[k3] = v3
                                        elseif type(v3) == 'table' then
                                            for k4, v4 in pairs(v3) do
                                                if type(v4) == 'number' or type(v4) == 'string' then
                                                    t[k4] = v4
                                                elseif type(v4) == 'table' then
                                                    for k5, v5 in pairs(v4) do
                                                        if type(v5) == 'number' or type(v5) == 'string' then
                                                            t[k5] = v5
                                                        end
                                                    end
                                                end
                                            end
                                        end
                                    end
                                end
                            end
                        end
                    end
                else
                    break
                end
                return t
            end

            for k, v in pairs(post_args) do
                t[#t+1] = k
            end

            return t
        else
            local t = {}
            for k, v in pairs(post_args) do
                t[#t+1] = k
            end

            return t
        end
    end
end


return _M
