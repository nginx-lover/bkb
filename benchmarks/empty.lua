
request = function()
    path = "/"
    wrk.headers["Accept"] = "*/*"
    wrk.headers["User-Agent"] = "Test"
    return wrk.format(nil, path)
end
