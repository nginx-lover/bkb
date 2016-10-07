local expat = require 'expat'

local myxml = [==[
<xml>
   <appid>wx2421b1c4370ec43b</appid>
   <mch_id>10000100</mch_id>
   <nonce_str>4ca93f17ddf3443ceabf72f26d64fe0e</nonce_str>
   <out_trade_no>1415983244</out_trade_no>
   <sign>59FF1DF214B2D279A0EA7077C54DD95D</sign>
</xml>
]==]
for k, v in pairs(expat) do 
	print(k, v)
end
