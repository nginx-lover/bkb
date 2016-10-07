use Test::Nginx::Socket 'no_plan';

my $workdir = $ENV{WORKDIR};

env_to_nginx("WAF-MODE=test", "WAF-DIR=$workdir");

our $http_config = <<"_EOC_";
  lua_shared_dict wafrule 10m;
  lua_package_path '$workdir/src/?.lua;;';
  lua_package_cpath '$workdir/src/clib/?.so;;';
  access_by_lua '
      local waf = require "waf"
      waf.use_x_forwarded_for = true
      waf.run()
  ';
_EOC_

repeat_each(1);
no_shuffle();
run_tests();

__DATA__

=== TEST1: test 1

--- http_config eval: $::http_config

--- config
location ~ .* {
    content_by_lua 'ngx.say("hello world")';
}

--- raw_request eval
"
GET /.git HTTP/1.0
Host: localhost

"

--- error_code: 403
=== TEST2: test 2

--- http_config eval: $::http_config

--- config
location ~ .* {
    content_by_lua 'ngx.say("hello world")';
}

--- raw_request eval
"
GET /1.php HTTP/1.0
Host: localhost

"

--- error_code: 403
=== TEST3: test 80

--- http_config eval: $::http_config

--- config
location ~ .* {
    content_by_lua 'ngx.say("hello world")';
}

--- raw_request eval
"
GET /1?a=1 HTTP/1.0
Host: localhost
Proxy: 192.168.1.1

"

--- error_code: 403

