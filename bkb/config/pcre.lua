local _M = {}
local getenv = os.getenv
local env = getenv('WAF-MODE')


if env == 'dev' then
    _M = {
        options = 'joU'
    }
elseif env == 'test' then
    _M = {
        options = 'joU'
    }
else
    _M = {
        options = 'joU'
    }
end

return _M
