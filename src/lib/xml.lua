local _M = {}
local lxp = require "lxp"


function _M.parse(xml)
    local t = {}
    pcall(function ()
        local callbacks = {
            StartElement = function (parser, name)
            end,
            EndElement = function (parser, name)
            end,
            CharacterData = function (parser, s)
            t[#t+1] = s
            end
        }

        p = lxp.new(callbacks)
        p:parse(xml)
        p:close()
    end)

    return t
end


return _M
