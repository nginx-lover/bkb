local _M = {}
local getenv = os.getenv
local env = getenv('WAF-MODE')


if env == 'dev' then
    _M = {
        host = '127.0.0.1',
        sock_type = 'tcp',
        port = 514,
        flush_limit = 4096,
        drop_limit = 1048576,
        timeout = 1000,
        periodic_flush = 1,
    }
elseif env == 'test' then
    _M = {
        host = '127.0.0.1',
        sock_type = 'tcp',
        port = 514,
        flush_limit = 4096,
        drop_limit = 1048576,
        timeout = 1000,
        periodic_flush = 1,
    }
else
    _M = {
        host = '127.0.0.1',
        sock_type = 'tcp',
        port = 514,
        flush_limit = 4096,
        drop_limit = 1048576,
        timeout = 1000,
        periodic_flush = 1,
    }
end

return _M
