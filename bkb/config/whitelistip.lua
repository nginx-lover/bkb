local _M = {}
local getenv = os.getenv
local env = getenv('WAF-MODE')


if env == 'dev' then
    _M = {
    }
elseif env == 'test' then
    _M = {
    }
else
    _M = {
      "127.0.0.1",
      "10.10.0.0/16",
    }
end

return _M
