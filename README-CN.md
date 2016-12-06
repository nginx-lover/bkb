[modsecurity]: https://www.modsecurity.org
[openresty]: https://github.com/openresty
[json]: http://www.json.org
[dota]: http://blog.dota2.com/
[BKB-API]: https://github.com/x-v8/bkb/blob/master/docs/API-CN.md
[BKB-TSAR]: https://github.com/detailyang/tsar-bkb.git

# bkb

<p align="center">
<img src="https://github.com/x-v8/bkb/blob/master/docs/Black_King_Bar_icon.png" />
</p>
黑皇杖在 [dota] 里的作用：获得技能免疫状态和100%的魔法抗性。持续时间和冷却时间每使用一次都会降低。部分终极技能的施放将无视天神下凡的效果。


# Description

BKB 在 [dota] 里代表黑皇杖，在这里我们用来指明 Web 防火墙。
黑皇杖在本项目指明 Web 防火墙，基于 [openresty] 实现的用来阻止恶意的 Web HTTP(s) 攻击。


# Feature

* 自动探查 - 探查机器人，爬虫，扫描者以及其他的恶意请求
* 常用的 Web 攻击保护 - XSS、SQL 注入、Shell注入
* 指定特征拦截 - 基于 URL 特征、Header 特征、请求参数特征的拦截
* 脆弱性的 BUG 提前修复 - 在后端 server 更新补丁之前， 提前修复已知的 vulnerability BUG。
* IP 拦截 - 带有生命周期的黑名单和白名单的流量拦截

# Todo

* CC攻击保护

# Other

[BKB-API]: BKB API文档     
[BKB-TSAR]: BKB tsar 插件    

# Principle

根据 cloudflare 在 2013 年发布的文章 [cloudflares-new-waf-compiling-to-lua](https://blog.cloudflare.com/cloudflares-new-waf-compiling-to-lua/)。 实现了第一个版本，从 [modsecurity] 规则集合到 Lua 代码块。由于编译器实现太过粗糙，重现实现了第二个版本，人肉翻译 [modsecurity]:(.

对于 [modsecurity] 规则集，它具有以下几个特点：

```lua
if operator(transform(variable), pattern) then
  action
else
  continue
end
```

正如你所见，任何 HTTP(s) 请求，都将经过以上 Lua 代码块。
根据这个规则，BKB 设计了一种通用的规则文件，以 [json] 格式存储，几乎可以被所有语言操纵。

```javascript
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
```

# Rule

## id

*字段含义*: 指明规则编号
*字段类型*: 整形


## phase

*字段含义*: 指明规则工作阶段
*字段类型*: 枚举字符串类型(access、header_filter、body_filter), 特别得为了跟 nginx 的 PHASE 相对应

原始的 [modsecurity] 工作阶段如下:
![phase](https://github.com/x-v8/bkb/blob/master/docs/modsecurity.jpeg)


## scope

*字段含义*: 规则作用域，指明规则修改的变量
*字段类型*: 枚举字符串类型 ('ip', 'uri', 'header', 'cookie', 'arg')

```python
SCOPECHOICE = (
    (0, 'ip'),
    (1, 'uri'),
    (2, 'header'),
    (3, 'cookie'),
    (4, 'arg'),
)
```

## tag

*字段含义*: 规则的标签
*字段类型*: 枚举字符串类型 ('XSS', 'SQLI', 'IP Deny', 'Shell Inject', 'URI Scan', 'PHPI', 'SCANNER', 'CVE')


```python
TAGCHOICE = (
    (0, 'XSS'),
    (1, 'SQLI'),
    (2, 'IP Deny'),
    (3, 'Shell Inject'),
    (4, 'URI Scan'),
    (5, 'PHPI'),
    (6, 'SCANNER'),
    (7, 'CVE')
)
```

## operator

*字段含义*: 规则的 operator 函数
*字段类型*: 枚举字符串类型 ( 'eq', 'rx', 'ipMatch', 'beginsWith', 'endsWith', 'ge', 'gt', 'lt', 'le', 'empty', 'nonEmpty', 'within', 'pmFromFile', 'pm')

```python
OPERATOR = [
    'eq', 'rx', 'ipMatch', 'beginsWith', 'endsWith', 'ge', 'gt', 'lt', 'le',
    'empty', 'nonEmpty', 'within', 'pmFromFile', 'pm'
]
```

## transform

*字段含义*: 规则的 transform 函数
*字段类型*: 枚举字符串类型 ('urlDecodeUni', 'jsDecode', 'lowercase', 'base64Decode', 'base64Encode', 'length', 'sha1', 'htmlEntityDecode', 'compressWhitespace', 'removeWhitespace', 'cssDecode')

```python
TRANSFORM = [
    'urlDecodeUni', 'jsDecode', 'lowercase', 'base64Decode', 'base64Encode',
    'length', 'sha1', 'htmlEntityDecode', 'compressWhitespace', 'removeWhitespace',
    'cssDecode'
]
```

## variable

*字段含义*: 规则要使用的变量
*字段类型*: 枚举的字符串类型 ('ip', 'uri', 'request_headers', 'request_cookies', 'args', 'matched_var')

```python
VARIABLE = [
    'ip', 'uri', 'request_headers', 'request_cookies', 'args', 'matched_var'
]
```

## pattern.type

*字段含义*: 规则要匹配的模式类型
*字段类型*: 目前只支持 string

## pattern.value

*字段含义*: 规则要匹配的模式值
*字段类型*: 字符串类型


## action

*字段含义*: 规则匹配到要执行的动作
*字段类型*: 枚举的字符串类型 ('deny', 'skip', 'log')

```python
ACTION = [
    'deny', 'skip', 'log'
]
```

## chain

*字段含义*: 规则链
*字段类型*: 数组类型（数组里的值指向规则)
