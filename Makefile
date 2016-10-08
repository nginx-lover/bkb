PATH := /usr/local/openresty/nginx/sbin:/usr/local/bin:$(PATH)
OS := $(shell uname)
ifeq ($(OS), Darwin)
    SO_EXT := dylib
else
    SO_EXT := so
endif

install:
	(cd deps && make lua-aho-corasick) && cp deps/lua-aho-corasick/ahocorasick.$(SO_EXT) src/clib/
	(cd deps && make lua-cjson) && cp deps/lua-cjson/cjson.$(SO_EXT) src/clib/
	(cd deps && make lua-expat) && cp deps/lua-expat/src/lxp.$(SO_EXT) src/clib/

clean:
	cd deps && make distclean

test:
	@WORKDIR=$(shell pwd) /usr/bin/prove

lint:
	luacheck src/
.PHONY: test lint install clean
