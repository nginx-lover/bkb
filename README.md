[modsecurity]: https://www.modsecurity.org
[openresty]: https://github.com/openresty
[json]: http://www.json.org

# BKB
<p align="center">
<img src="https://github.com/x-v8/bkb/blob/master/docs/Black_King_Bar_icon.png" />
</p>
Black King Bar (also known as BKB) is an Armor item purchasable from the Home Shop. When the Avatar ability is activated, Spell Immunity and 100% Magic Resistance are granted to the user for a short period of time.


#Description
BKB in here is the web application firewall (WAF), it's based on the [OpenResty] under the hood.
It 's used to prevent malignant web attack from HTTP(s). And it's insired by the [modsecurity] and can be compatibled with the modsecurity rules.

#Principle
According the cloudflare blog post in 2013 [cloudflares-new-waf-compiling-to-lua](https://blog.cloudflare.com/cloudflares-new-waf-compiling-to-lua/), I implement the first version which it's not so good. I carefully think that the [modsecurity] rules compiling to the lua code chunk is not perfect and the compiler which i implement is dirty:(. So i reading the [modsecurity] rules carefully, then design the second version.

From the [modsecurity] rules, it can be demonstrated as the following:

````lua
if operator(variable, pattern) then
  action
else
  continue
end
````
As you see, any HTTP request will go through the code chunk above.

So I design the universal rule [json] format which can be manipulated by almost programing language as the following:
````javascript
  {
    "action": [
      {
        "name": "deny",
        "param": "null"
      }
    ],
    "chain": [],
    "id": 1,
    "operator": {
      "name": "rx",
      "reverse": false
    },
    "pattern": {
      "type": "string",
      "value": "\\.(git|svn)$"
    },
    "phase": "access",
    "scope": "uri",
    "tag": 4,
    "transform": [],
    "variable": [
      {
        "key": "",
        "match": "eq",
        "name": "uri",
        "reverse": false
      }
    ]
  }
````

#Rule

##phase
*desc*: rule 's work phase

It can be consist of access、header_filter、body_filter and It's fit for nginx http phase specially.

the origin modsecurity rule's phase is the following:
![phase](https://github.com/x-v8/bkb/blob/master/docs/modsecurity.jpeg)

