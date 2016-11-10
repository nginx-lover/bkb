````json
  {
    "id": 1,
    "phase": "access",
    "scope": "uri",
    "tag": 4,
    "operator": {
      "name": "rx",
      "reverse": false
    },
    "transform": [],
    "variable": [
      {
        "key": "",
        "match": "eq",
        "name": "uri",
        "reverse": false
      }
    ],
    "pattern": {
      "type": "string",
      "value": "\\.(git|svn)$"
    },
    "action": [
      {
        "name": "deny",
        "param": "null"
      }
    ],
    "chain": []
  }
````

````bash
rule: {
  id
  phase
  scope
  tag
  operator
  transform
  variable
  pattern
  action
  chain
}

id: number

phase:
  | "access"
  | "header_filter"
  | "body_filter"

scope:
  | "ip"
  | "uri"
  | "header"
  | "cookie"
  | "arg"

tag:
  | "XSS"
  | "SQLI"
  | "IP Deny"
  | "Shell Inject"
  | "URI Scan"
  | "PHPI"
  | "SCANNER"
  | "CVE"

operator: {
  name:
    | "eq"
    | "rx"
    | "ipMatch"
    | "beginsWith"
    | "endsWith"
    | "ge"
    | "gt"
    | "lt"
    | "empty"
    | "nonEmpty"
    | "within"
    | "pmFromFile"
    | "pm"
  reverse: boolean
}

transform: [
{
  name:
    | "urlDecodeUni"
    | "jsDecode"
    | "cssDecode"
    | "lowercase"
    | "base64Decode"
    | "base64Encode"
    | "length"
    | "sha1"
    | "htmlEntityDecode"
    | "compressWhitespace"
    | "removeWhitespace"
}
]

variable: [
{
  name:
    | "ip"
    | "uri"
    | "request_headers"
    | "request_cookies"
    | "args"
    | "matched_var"
  key: string
  match:
    | "eq"
    | "rx"
    | "all"
  reverse: bool
}
]

pattern: {
  type:
    | "string"
  value: string
}

action: [
{
  name:
    | "deny"
    | "skip"
    | "log"
  param: string
}
]

chain: [
rule
]
````
