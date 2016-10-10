use Test::Nginx::Socket 'no_plan';
use Time::HiRes qw( time );

my $workdir = $ENV{WORKDIR};

env_to_nginx("WAF-MODE=test", "WAF-DIR=$workdir");

our $http_config = <<"_EOC_";
  lua_shared_dict wafrule 10m;
  lua_package_path '$workdir/?.lua;;';
  lua_package_cpath '$workdir/bkb/clib/?.so;;';
  access_by_lua '
      local waf = require "bkb.waf"
      waf.use_x_forwarded_for = true
      waf.run()
  ';
_EOC_

repeat_each(1);
no_shuffle();
run_tests();

__DATA__

=== TEST1:   whitelist  test access by 223.240.53.221

--- http_config eval: $::http_config

--- config
location = /1 {
    content_by_lua 'ngx.say("hello world")';
}

--- request
GET /1

--- more_headers
X-Forwarded-For: 223.240.53.221
--- error_code eval
my $elapsed = int(time());
my $code = "";
if ($elapsed <= 1506675534) {
      $code = 403;
  } else {
      $code = 200;
  }
$code


=== TEST2:   whitelist  test access by 1.2.3.4

--- http_config eval: $::http_config

--- config
location = /1 {
    content_by_lua 'ngx.say("hello world")';
}

--- request
GET /1

--- more_headers
X-Forwarded-For: 1.2.3.4
--- error_code eval
my $elapsed = int(time());
my $code = "";
if ($elapsed <= 1477106437) {
      $code = 403;
  } else {
      $code = 200;
  }
$code

