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

local t = _M.parse([==[
<xml>
   <return_code><![CDATA[SUCCESS]]></return_code>
   <return_msg><![CDATA[OK]]></return_msg>
   <appid><![CDATA[wx2421b1c4370ec43b]]></appid>
   <mch_id><![CDATA[10000100]]></mch_id>
   <nonce_str><![CDATA[BFK89FC6rxKCOjLX]]></nonce_str>
   <sign><![CDATA[72B321D92A7BFA0B2509F3D13C7B1631]]></sign>
   <result_code><![CDATA[SUCCESS]]></result_code>
</xml>
]==])
for k, v in pairs(t) do
end

return _M

