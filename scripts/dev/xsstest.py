#! /usr/bin/python
# -*- coding: utf-8 -*-


import requests


res = requests.get('https://gist.githubusercontent.com/JohannesHoppe/5612274/raw/60016bccbfe894dcd61a6be658a4469e403527de/666_lines_of_XSS_vectors.html')
PREFIX = 'http://192.168.33.10/index?xss='
whitelist = {
	'548': 1,
	'551': 1,
	'578': 1,
	'591': 1,
	'595': 1,
	'596': 1,
	'605': 1,
	'606': 1,
}
i = 0


for xss in res.text.splitlines():
	i = i + 1
	if str(i) in whitelist:
		continue
	url = '%s%s' %(PREFIX, xss)
	res = requests.get(url)
	if res.status_code != 403:
		print("%s error line: %d" %(url,i))
		break
	else:
		print("%s pass" %url)


