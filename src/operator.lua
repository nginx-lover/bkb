local _M = {}

local inject = require ("lib.injection")
local iputils = require("lib.resty.iputils")
local utf8 = require("lib.utf8_validator")
local util = require("util")
local iputils = require("lib.resty.iputils")
local ac = require("lib.ac")

iputils.enable_lrucache()

local parse_cidrs = iputils.parse_cidrs
local ip_in_cidrs = iputils.ip_in_cidrs
local ct = util.count_table
local string_find = string.find
local string_sub = string.sub
local match = ngx.re.match
local find = ngx.re.find
local ngx_exit = ngx.exit
local ngx_log = ngx.log
local ERR = ngx.ERR
local ac_create = ac.create
local ac_match = ac.match
local URLCharacters = {
    ["!"] = 1, ["*"] = 1, ["'"] = 1, ["("] = 1, [")"] = 1, [";"] = 1, [":"] = 1, ["@"] = 1, ["&"] = 1, ["="] = 1, ["+"] = 1, ["$"] = 1, [","] = 1, ["/"] = 1, ["?"] = 1, ["#"] = 1, ["["] = 1, ["]"] = 1, [" "] = 1,["A"] = 1, ["B"] = 1, ["C"] = 1, ["D"] = 1, ["E"] = 1, ["F"] = 1, ["G"] = 1, ["H"] = 1, ["I"] = 1, ["J"] = 1, ["K"] = 1, ["L"] = 1, ["M"] = 1, ["N"] = 1, ["O"] = 1, ["P"] = 1, ["Q"] = 1, ["R"] = 1, ["S"] = 1, ["T"] = 1, ["U"] = 1, ["V"] = 1, ["W"] = 1, ["X"] = 1, ["Y"] = 1, ["Z"] = 1, [" "] = 1,["a"] = 1, ["b"] = 1, ["c"] = 1, ["d"] = 1, ["e"] = 1, ["f"] = 1, ["g"] = 1, ["h"] = 1, ["i"] = 1, ["j"] = 1, ["k"] = 1, ["l"] = 1, ["m"] = 1, ["n"] = 1, ["o"] = 1, ["p"] = 1, ["q"] = 1, ["r"] = 1, ["s"] = 1, ["t"] = 1, ["u"] = 1, ["v"] = 1, ["w"] = 1, ["x"] = 1, ["y"] = 1, ["z"] = 1, [" "] = 1,["0"] = 1, ["1"] = 1, ["2"] = 1, ["3"] = 1, ["4"] = 1, ["5"] = 1, ["6"] = 1, ["7"] = 1, ["8"] = 1, ["9"] = 1, ["-"] = 1, ["_"] = 1, ["."]=1, ["~"] = 1,[" "] = 1
}
local cc2_table = {
    ["0"] = 0, ["1"] = 2, ["2"] = 4, ["3"] = 6, ["4"] = 8, ["5"] = 1, ["6"] = 3, ["7"] = 5, ["8"] = 7, ["9"] = 9,
}
local cc_table = {
    ["0"] = 0, ["1"] = 1, ["2"] = 2, ["3"] = 3, ["4"] = 4, ["5"] = 5, ["6"] = 6, ["7"] = 7, ["8"] = 8, ["9"] = 9,
}
local n2s_table = {
    [0] = "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "100",
}
local ac_cache = {}
local ac_cache_index = {}
local validateByteRange_cache = {}


function _M.validateUtf8Encoding(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _validateUtf8Encoding(waf, ctx, variable, pattern)
        return utf8.validate(variable)
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _validateUtf8Encoding(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _validateUtf8Encoding(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _validateUtf8Encoding(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.always(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    if reverse then
        return not false
    else
        return true
    end
end


function _M.empty(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _empty(waf, ctx, variable, pattern)
        if #variable == 0 then
            return true
        else
            return false
        end
    end


    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _empty(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _empty(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _empty(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.nonEmpty(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _nonEmpty(waf, ctx, variable, pattern)
        if #variable > 0 then
            return true
        else
            return false
        end
    end


    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _nonEmpty(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _nonEmpty(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _nonEmpty(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.unconditionalMatch(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _unconditionalMatch(waf, ctx, variable, pattern)
        ctx.TX[1] = variable
        ctx.TX['1'] = variable
        return true
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _unconditionalMatch(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _unconditionalMatch(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _unconditionalMatch(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.rsub(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    if reverse then
        return true
    else
        return false
    end
end


-- maybe shoule be implement in real block list
function _M.rbl(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    if reverse then
        return true
    else
        return false
    end
end


function _M.geoLookup(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    if reverse then
        return true
    else
        return false
    end
end


function _M.verifyCC(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _verifyCC(waf, ctx, variable, pattern)
        local captures, err = match(variable, pattern, waf.pcre.options)
        if err then
            return false
        end

        local card = ""
        for i = 1, #variable do
            local c = variable:sub(i, i)
            if c <= '9' and c >= '0' then
                card = card .. c
            end
        end

        local even = 0
        local verify = 0

        -- last number is verify code
        for i = #card-1, 1, -1 do
            local c = card:sub(i, i)
            if even % 2 == 0 then
                verify = verify + cc2_table[c]
            else
                verify = verify + cc_table[c]
            end
            even = even + 1
        end

        local m = verify % 10
        local z = 0

        if (m ~= 0) then
            z = 10 - m
        end

        return z == cc_table[card:sub(#card, #card)]
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _verifyCC(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _verifyCC(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _verifyCC(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end

function _M.within(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _within(waf, ctx, variable, pattern)
        local from, to, err = find(pattern, variable, waf.pcre.options)

        if from then
            return true
        else
            return false
        end
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _within(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _within(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _within(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.validateUrlEncoding(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _validateUrlEncoding(waf, ctx , variable, pattern)
        for i = 1, #variable do
            local c = variable:sub(i, i)
            if not URLCharacters[c] then
                return false
            end
        end

        return true
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _validateUrlEncoding(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _validateUrlEncoding(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _validateUrlEncoding(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.pmFromFile(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _pmFromFile(waf, ctx, variable, pattern)
        local pm = {}
        local pos = 1
        local mation = nil

        if ac_cache[id] ~= nil then
            mation = ac_cache[id]
        else
            if ac_cache_index[id] then
                for k, v in pairs(pattern) do
                    pm[#pm + 1] = v
                end
            else
                ac_cache_index[id] = {}
                for k, v in pairs(pattern) do
                    pm[#pm + 1] = v
                    ac_cache_index[id][v] = 1
                end
            end

            mation = nil
            mation = ac_create(pm)
            ac_cache[id] = mation
        end

        local b, e = ac_match(mation, variable)

        if b ~= nil and b >= 0 then
            ctx.dynamic['matched_var'] = variable
            return true
        end

        return false
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _pmFromFile(waf, ctx, v1, waf.file[pattern]) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _pmFromFile(waf, ctx, v, waf.file[pattern]) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _pmFromFile(waf, ctx, variable, waf.file[pattern])
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.pm(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _pm(waf, ctx, variable, pattern)
        local pm = {}
        local pos = 1

        for i = 1, #pattern do
            local c = pattern:sub(i,i)
            if c == " " then
                pm[#pm + 1] = pattern:sub(pos, i-1)
                pos = i+1
            end
        end
        if pos ~= #pattern then
            pm[#pm + 1] = pattern:sub(pos, #pattern)
        end

        local mation = nil
        if ac_cache[id] then
            mation = ac_cache[id]
        else
            mation = ac_create(pm)
            ac_cache[id] = mation
        end

        local m = ac_match(mation, variable)

        if m ~= nil and m >= 0 then
            ctx.dynamic['matched_vars'] = variable
            return true
        end

        return false
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _pm(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _pm(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _pm(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.inspectFile(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    if reverse then
        return true
    else
        return false
    end
end

function _M.detectSQLi(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _detectSQLi(waf, ctx, variable, pattern)
        return inject.sqli(variable)
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _detectSQLi(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _detectSQLi(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _detectSQLi(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.detectXSS(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _detectXSS(waf, ctx, variable, pattern)
        if inject.xss(variable) then
            return true
        else
            return false
        end
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _detectXSS(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _detectXSS(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _detectXSS(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.beginsWith(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _beginsWith(waf, ctx, variable, pattern)
        return string_sub(variable, 1, #pattern) == pattern
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _beginsWith(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _beginsWith(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _beginsWith(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.endsWith(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _endsWith(waf, ctx, variable, pattern)
        return string_sub(variable, -#pattern) ==pattern
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _endsWith(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _endsWith(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _endsWith(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.contains(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _contains(waf, ctx, variable, pattern)
        local from, to, err = find(variable, pattern, waf.pcre.options)

        if from then
            return true
        else
            return false
        end
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _contains(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _contains(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _contains(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.containsWord(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _containsWord(waf, ctx, variable, pattern)
        local from, to, err = find(variable, pattern, waf.pcre.options)

        if from then
            return true
        else
            return false
        end
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _containsWord(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _containsWord(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _containsWord(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.streq(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _streq(waf, ctx, variable, pattern)
        return variable == pattern
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _streq(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _streq(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _streq(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.eq(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _eq(waf, ctx, variable, pattern)
        return variable == pattern
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _eq(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _eq(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _eq(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.le(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _le(waf, ctx, variable, pattern)
        return tonumber(variable) <= tonumber(pattern)
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _le(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _le(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _le(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.ge(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _ge(waf, ctx, variable, pattern)
        return tonumber(variable) >= tonumber(pattern)
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _ge(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _ge(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _ge(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.gt(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _gt(waf, ctx, variable, pattern)
        if variable == "" then
            return 0 > tonumber(pattern)
        end
        return tonumber(variable) > tonumber(pattern)
    end

    if type(variable) == 'function' then
        variable = variable()
    end
    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            local sign = t_name .. v_name .. k
            if ctx._cache[sign] then
                v = ctx._cache[sign]
            else
                for _, transform in pairs(transforms) do
                    v = transform(waf, v)
                end
                ctx._cache[sign] = v
            end
            if _gt(waf, ctx, v, pattern) == true then
                rv = true
                break
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _gt(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.lt(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _lt(waf, ctx, variable, pattern)
        return tonumber(variable) <= tonumber(pattern)
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _lt(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _lt(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _lt(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.ipMatch(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _ipMatch(waf, ctx, variable, pattern)
        local p = parse_cidrs({pattern})
        return ip_in_cidrs(variable, p)
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _ipMatch(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _ipMatch(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _ipMatch(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.rx(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _rx(waf, ctx, variable, pattern)
        local captures, err = match(variable, pattern, waf.pcre.options)
        if err then
            return false
        end

        if captures then
            for i = 0, #captures + 1 do
                ctx.dynamic['matched_var' .. n2s_table[i]] = captures[i]
                ctx.dynamic[tonumber(n2s_table[i])] = captures[i]
            end
            return true
        end

        return false
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _rx(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _rx(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _rx(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.validateByteRange(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _validateByteRange (waf, ctx, variable, pattern)
        local ranges = util.split(pattern, ',')
        local section = {}
        local e_section = {}
        local target = tonumber(variable)

        if target == nil then
            return false
        end

        if validateByteRange_cache[id] then
            e_section = validateByteRange_cache[id]['e_section']
            section = validateByteRange_cache[id]['section']
        else
            for k, v in pairs(ranges) do
                local during = util.split(v, '-')
                if #during == 1 then
                    local e = tonumber(during[1])
                    if e ~= nil then
                        e_section[#e_section] = e
                    end
                else
                    if #during == 2 then
                        local a = tonumber(during[1])
                        local b = tonumber(during[2])
                        if a ~= nil and b ~= nil then
                            section[#section + 1] = {a, b}
                        end
                    end
                end
            end
            validateByteRange_cache[id] = {
                ['e_section'] = e_section,
                ['section'] = section
            }
        end

        for k, v in pairs(section) do
            if target >= v[1] and target <= v[2] then
                return false
            end
        end
        for k, v in pairs(e_section) do
            if v == target then
                return true
            end
        end

        return false
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _validateByteRange(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _validateByteRange(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _validateByteRange(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end


function _M.strmatch(waf, ctx, id, reverse, transforms, t_name, variable, v_name, pattern)
    local function _strmatch(waf, ctx, variable, pattern)
        local n, m = #variable, #pattern

        if m > n then
            return false
        end

        local char = {}

        for k = 0, 255 do char[k] = m end
        for k = 1, m-1 do char[pattern:sub(k, k):byte()] = m - k end

        local k = m
        while k <= n do
            local i, j = k, m

            while j >= 1 and variable:sub(i, i) == pattern:sub(j, j) do
                i, j = i - 1, j - 1
            end

            if j == 0 then
                return true
            end

            k = k + char[variable:sub(k, k):byte()]
        end

        return false
    end

    if type(variable) == 'function' then
        variable = variable()
    end

    local rv = false
    if variable == nil then
        rv = false
    elseif type(variable) == 'table' then
        for k, v in pairs(variable) do
            if type(v) == 'table' then
                for k1, v1 in pairs(v) do
                    local sign = t_name .. v_name .. k .. k1
                    if ctx._cache[sign] then
                        v1 = ctx._cache[sign]
                    else
                        for _, transform in pairs(transforms) do
                            v1 = transform(waf, v1)
                        end
                        ctx._cache[sign] = v1
                    end
                    if _strmatch(waf, ctx, v1, pattern) == true then
                        rv = true
                        break
                    end
                end
            elseif type(v) == 'string' then
                local sign = t_name .. v_name .. k
                if ctx._cache[sign] then
                    v = ctx._cache[sign]
                else
                    for _, transform in pairs(transforms) do
                        v = transform(waf, v)
                    end
                    ctx._cache[sign] = v
                end
                if _strmatch(waf, ctx, v, pattern) == true then
                    rv = true
                    break
                end
            else
                rv = false
            end
        end
    elseif type(variable) == 'string' or type(variable) == 'number' then
        local sign = t_name .. v_name
        if ctx._cache[sign] then
            variable = ctx._cache[sign]
        else
            for _, transform in pairs(transforms) do
                variable = transform(waf, variable)
            end
            ctx._cache[sign] = variable
        end
        rv = _strmatch(waf, ctx, variable, pattern)
    end

    if reverse then
        return not rv
    else
        return rv
    end
end

return _M
