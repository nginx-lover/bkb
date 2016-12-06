BKB 提供了以下的 API， 使得在运行时获取或者修改状态。

GET /waf
=====

`curl -H "Host: bkb" http://127.0.0.1:80/waf`

返回值:

```
{
  "trigger": 8251,
  "delay": 1169,
  "dry": true,
  "maxdelay": 20799346,
  "run": true,
  "totalcnt": 1760868,
  "totaldelay": 2060066179,
  "waf_mode_file": "/data/waf/mode"
  "ip_version": 1476071437,
  "rule_version": 1481013416,
}
```

含义如下:

*delay*: 平均延时

*dry*: 是否开启观察者模式

*maxdelay*: 最大延迟

*run*: 是否开启防火墙

*totalcnt*： 总的分析请求次数

*totaldelay*: 总的延迟

*waf_mode_file*: 持久化状态保存的文件

*ip_version*: IP 白名单版本

*rule_version*: RULE集版本



POST /waf
=========

`curl -H "Host: bkb" -X POST -d "dry=0|1" "http://127.0.0.1:80/waf"`

设置防火墙是否开启观察者模式

POST /waf
=========

`curl -H "Host: bkb" -X POST -d "run=0|1" "http://127.0.0.1:80/waf"`

设置防火墙是否开启


PUT /ip
=========
`curl -H "Host: bkb" -X PUT "http://127.0.0.1:80/ip`

热更新 IP 白名单和黑名单


PUT /rule
`curl -H "Host: bkb" -X PUT "http://127.0.0.1:80/rule`

热更新 RULE集
