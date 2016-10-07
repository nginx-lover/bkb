#! /usr/bin/python
# -*- coding: utf-8 -*-
# please make sure you use python > 3


import requests


res = requests.get('https://gist.githubusercontent.com/JohannesHoppe/5612274/raw/60016bccbfe894dcd61a6be658a4469e403527de/666_lines_of_XSS_vectors.html')
PREFIX = 'http://192.168.33.10?xss='
i = 0
whitelist = {
	'491': 1,
	'548': 1,
	'551': 1,
	'566': 1,
	'578': 1,
	'591': 1,
	'595': 1,
	'596': 1,
	'605': 1,
	'606': 1,
}


for xss in res.text.splitlines():
    i = i + 1
    if str(i) in whitelist:
    	continue
    print('''
=== TEST#i#: #title#
--- http_config eval: $::http_config
--- config
location /abcd {
  root html;
}
--- request
GET /abcd?xss=#v#
--- error_code: 403'''.replace('#i#', str(i)).replace('#title#', xss[:20]).replace('#v#', xss.replace(' ', '%20')))
