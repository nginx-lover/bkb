local _M = {
    _VERSION = 1475139904
}
local util = require("util")
local waf_util_get_field_from_table = util.get_field_from_table
local waf_util_merge_tables = util.merge_tables
local waf_util_get_cookies = util.get_cookies
local waf_util_get_table_names = util.get_table_names
local waf_util_remove_boolean_and_table = util.remove_boolean_and_table
local waf_util_get_post_args = util.get_post_args
local waf_util_get_table_value = util.get_table_value
local waf_util_merge_table = util.merge_table

local waf = require("waf")
local get_uri_args = ngx.req.get_uri_args
local get_post_args = ngx.req.get_post_args
local get_headers = ngx.req.get_headers
local get_method = ngx.req.get_method
local raw_header = ngx.req.raw_header
local string_upper = string.upper
local get_phase = ngx.get_phase


-----------------------------------
--------------action---------------
-----------------------------------
local waf_action_skip = waf.action.skip
local waf_action_deny = waf.action.deny

-----------------------------------
--------------operator-------------
-----------------------------------
local waf_operator_ipMatch = waf.operator.ipMatch
local waf_operator_beginsWith = waf.operator.beginsWith
local waf_operator_endsWith = waf.operator.endsWith
local waf_operator_rx = waf.operator.rx
local waf_operator_eq = waf.operator.eq
local waf_operator_streq = waf.operator.streq
local waf_operator_pmFromFile = waf.operator.pmFromFile
local waf_operator_pm = waf.operator.pm
local waf_operator_nonEmpty = waf.operator.nonEmpty
local waf_operator_empty = waf.operator.empty


function _M.run(waf, ctx)
    local phase = get_phase()

    -----------------------------------
    --------------variable-------------
    -----------------------------------
    local waf_variable_ip = ngx.var.remote_addr
    if waf.use_x_forwarded_for then
        waf_variable_ip = get_headers()['x-forwarded-for'] or ngx.var.remote_addr
    end
    local waf_variable_uri = ngx.var.uri

    local waf_variable_request_headers = get_headers() or {}
    local waf_variable_request_cookies = waf_util_get_cookies() or {}

    local waf_variable_args_post, waf_variable_files_names = waf_util_get_post_args()
    if waf_variable_args_post == nil then
        waf_variable_args_post = {}
    end
    local waf_variable_args_get = waf_util_remove_boolean_and_table(get_uri_args() or {})
    local waf_variable_args = waf_util_merge_table(waf_variable_args_get, waf_variable_args_post)
    local waf_variable_args_get_names = waf_util_get_table_names(waf_variable_args)
    local waf_variable_args_get_value = waf_util_get_table_value(waf_variable_args)
    ctx.body = waf_variable_args_post
    local waf_variable_args_names = waf_util_get_table_names(waf_variable_args)

    -----------------------------------
    --------------variable-------------
    -----------------------------------
    local waf_transform_htmlEntityDecode = waf.transform.htmlEntityDecode
    local waf_transform_jsDecode = waf.transform.jsDecode
    local waf_transform_cssDecode = waf.transform.cssDecode
    local waf_transform_lowercase = waf.transform.lowercase
    local waf_transform_compressWhitespace = waf.transform.compressWhitespace


    local v = {}
    local t = {}


    v._0 = waf_variable_uri
                        v._1 = waf_variable_uri
                        v._2 = waf_variable_args
                        v._3 = function () return ctx.dynamic['matched_var']
                        end
            v._4 = waf_variable_request_headers['user-agent']
                        v._5 = waf_variable_request_headers['proxy']
                        t._0 = {  }
    t._1 = { waf_transform_htmlEntityDecode,waf_transform_jsDecode,waf_transform_cssDecode, }
    t._2 = { waf_transform_htmlEntityDecode,waf_transform_jsDecode, }
    t._3 = { waf_transform_htmlEntityDecode,waf_transform_compressWhitespace, }
    t._4 = { waf_transform_lowercase, }
    

    if phase == "access" then
        -----------------------------------
        ----------------IP-----------------
        -----------------------------------
        
        -----------------------------------
        ----------------uri----------------
        -----------------------------------
                    if waf_operator_rx(waf, ctx, '1',  false ,  t._0, 't._0', v._0, 'v_0', [==[\.(git|svn)$]==]) then
                waf_action_deny(waf, ctx, '1', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '2',  false ,  t._0, 't._0', v._1, 'v_1', [==[\.(php|java|jsp|asp)$]==]) then
                waf_action_deny(waf, ctx, '2', [==[null]==])
                return
            end
        
        -----------------------------------
        ----------------header-------------
        -----------------------------------
                    if waf_operator_pmFromFile(waf, ctx, '78',  false ,  t._0, 't._0', v._4, 'v_4', [==[scanners-user-agents.data]==]) then
                waf_action_deny(waf, ctx, '78', [==[null]==])
                return
            end
                    if waf_operator_nonEmpty(waf, ctx, '80',  false ,  t._0, 't._0', v._5, 'v_5', [==[anything]==]) then
                waf_action_deny(waf, ctx, '80', [==[null]==])
                return
            end
        
        -----------------------------------
        ----------------cookie-------------
        -----------------------------------
        
        -----------------------------------
        ----------------args---------------
        -----------------------------------
                    if waf_operator_rx(waf, ctx, '4',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:(sleep\((\s*?)(\d*?)(\s*?)\)|benchmark\((.*?)\,(.*?)\)))]==]) then
                waf_action_deny(waf, ctx, '4', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '5',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:(?:(select|;)\s+(?:benchmark|if|sleep)\s*?\(\s*?\(?\s*?\w+))]==]) then
                waf_action_deny(waf, ctx, '5', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '6',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:(?:\sexec\s+xp_cmdshell)|(?:[\"'`]\s*?!\s*?[\"'`\w])|(?:from\W+information_schema\W)|(?:(?:(?:current_)?user|database|schema|connection_id)\s*?\([^\)]*?)|(?:[\"'`];?\s*?(?:select|union|having)\s*?[^\s])|(?:\wiif\s*?\()|(?:exec\s+master\.)|(?:union select @)|(?:union[\w(\s]*?select)|(?:select.*?\w?user\()|(?:into[\s+]+(?:dump|out)file\s*?[\"'`]))]==]) then
                waf_action_deny(waf, ctx, '6', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '7',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:(?:^(-0000023456|4294967295|4294967296|2147483648|2147483647|0000012345|-2147483648|-2147483649|0000023456|3.0.00738585072007e-308|1e309)$))]==]) then
                waf_action_deny(waf, ctx, '7', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '8',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:(?:[\s()]case\s*?\()|(?:\)\s*?like\s*?\()|(?:having\s*?[^\s]+\s*?[^\w\s])|(?:if\s?\([\d\w]\s*?[=<>~]))]==]) then
                waf_action_deny(waf, ctx, '8', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '9',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:(?:alter\s*?\w+.*?character\s+set\s+\w+)|([\"'`];\s*?waitfor\s+time\s+[\"'`])|(?:[\"'`];.*?:\s*?goto))]==]) then
                waf_action_deny(waf, ctx, '9', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '10',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:(?:merge.*?using\s*?\()|(execute\s*?immediate\s*?[\"'`])|(?:match\s*?[\w(),+-]+\s*?against\s*?\())]==]) then
                waf_action_deny(waf, ctx, '10', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '11',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:(?:(union(.*?)select(.*?)from)))]==]) then
                waf_action_deny(waf, ctx, '11', [==[null]==])
                return
            end
                    if waf_operator_eq(waf, ctx, '12',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:(?:select\s*?pg_sleep)|(?:waitfor\s*?delay\s?[\"'`]+\s?\d)|(?:;\s*?shutdown\s*?(?:;|--|#|\/\*|{)))]==]) then
                waf_action_deny(waf, ctx, '12', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '13',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:(?:\[\$(?:ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|x?or|div|like|between|and)\]))]==]) then
                waf_action_deny(waf, ctx, '13', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '14',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:(?:procedure\s+analyse\s*?\()|(?:;\s*?(declare|open)\s+[\w-]+)|(?:create\s+(procedure|function)\s*?\w+\s*?\(\s*?\)\s*?-)|(?:declare[^\w]+[@#]\s*?\w+)|(exec\s*?\(\s*?@))]==]) then
                waf_action_deny(waf, ctx, '14', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '15',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:(?:create\s+function\s+\w+\s+returns)|(?:;\s*?(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*?[\[(]?\w{2,}))]==]) then
                waf_action_deny(waf, ctx, '15', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '24',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:(?:\)\s*?when\s*?\d+\s*?then)|(?:[\"'`]\s*?(?:#|--|{))|(?:\/\*!\s?\d+)|(?:ch(?:a)?r\s*?\(\s*?\d)|(?:(?:(n?and|x?x?or|div|like|between|and|not)\s+|\|\||\&\&)\s*?\w+\())]==]) then
                waf_action_deny(waf, ctx, '24', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '31',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i)\b(?i:and)\b\s+(\d{1,10}|'[^=]{1,10}')\s*?[=]|\b(?i:and)\b\s+(\d{1,10}|'[^=]{1,10}')\s*?[<>]|\band\b ?(?:\d{1,10}|[\'\"][^=]{1,10}[\'\"]) ?[=<>]+|\b(?i:and)\b\s+(\d{1,10}|'[^=]{1,10}')]==]) then
                waf_action_deny(waf, ctx, '31', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '32',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:(?:(?:s(?:t(?:d(?:dev(_pop|_samp)?)?|r(?:_to_date|cmp))|u(?:b(?:str(?:ing(_index)?)?|(?:dat|tim)e)|m)|e(?:c(?:_to_time|ond)|ssion_user)|ys(?:tem_user|date)|ha(1|2)?|oundex|chema|ig?n|pace|qrt)|i(?:s(null|_(free_lock|ipv4_compat|ipv4_mapped|ipv4|ipv6|not_null|not|null|used_lock))?|n(?:et6?_(aton|ntoa)|s(?:ert|tr)|terval)?|f(null)?)|u(?:n(?:compress(?:ed_length)?|ix_timestamp|hex)|tc_(date|time|timestamp)|p(?:datexml|per)|uid(_short)?|case|ser)|l(?:o(?:ca(?:l(timestamp)?|te)|g(2|10)?|ad_file|wer)|ast(_day|_insert_id)?|e(?:(?:as|f)t|ngth)|case|trim|pad|n)|t(?:ime(stamp|stampadd|stampdiff|diff|_format|_to_sec)?|o_(base64|days|seconds|n?char)|r(?:uncate|im)|an)|m(?:a(?:ke(?:_set|date)|ster_pos_wait|x)|i(?:(?:crosecon)?d|n(?:ute)?)|o(?:nth(name)?|d)|d5)|r(?:e(?:p(?:lace|eat)|lease_lock|verse)|o(?:w_count|und)|a(?:dians|nd)|ight|trim|pad)|f(?:i(?:eld(_in_set)?|nd_in_set)|rom_(base64|days|unixtime)|o(?:und_rows|rmat)|loor)|a(?:es_(?:de|en)crypt|s(?:cii(str)?|in)|dd(?:dat|tim)e|(?:co|b)s|tan2?|vg)|p(?:o(?:sition|w(er)?)|eriod_(add|diff)|rocedure_analyse|assword|i)|b(?:i(?:t_(?:length|count|x?or|and)|n(_to_num)?)|enchmark)|e(?:x(?:p(?:ort_set)?|tract(value)?)|nc(?:rypt|ode)|lt)|v(?:a(?:r(?:_(?:sam|po)p|iance)|lues)|ersion)|g(?:r(?:oup_conca|eates)t|et_(format|lock))|o(?:(?:ld_passwo)?rd|ct(et_length)?)|we(?:ek(day|ofyear)?|ight_string)|n(?:o(?:t_in|w)|ame_const|ullif)|(rawton?)?hex(toraw)?|qu(?:arter|ote)|(pg_)?sleep|year(week)?|d?count|xmltype|hour)\W*?\(|\b(?:(?:s(?:elect\b(?:.{1,100}?\b(?:(?:length|count|top)\b.{1,100}?\bfrom|from\b.{1,100}?\bwhere)|.*?\b(?:d(?:ump\b.*?\bfrom|ata_type)|(?:to_(?:numbe|cha)|inst)r))|p_(?:sqlexec|sp_replwritetovarbin|sp_help|addextendedproc|is_srvrolemember|prepare|sp_password|execute(?:sql)?|makewebtask|oacreate)|ql_(?:longvarchar|variant))|xp_(?:reg(?:re(?:movemultistring|ad)|delete(?:value|key)|enum(?:value|key)s|addmultistring|write)|terminate|xp_servicecontrol|xp_ntsec_enumdomains|xp_terminate_process|e(?:xecresultset|numdsn)|availablemedia|loginconfig|cmdshell|filelist|dirtree|makecab|ntsec)|u(?:nion\b.{1,100}?\bselect|tl_(?:file|http))|d(?:b(?:a_users|ms_java)|elete\b\W*?\bfrom)|group\b.*?\bby\b.{1,100}?\bhaving|open(?:rowset|owa_util|query)|load\b\W*?\bdata\b.*?\binfile|(?:n?varcha|tbcreato)r|autonomous_transaction)\b|i(?:n(?:to\b\W*?\b(?:dump|out)file|sert\b\W*?\binto|ner\b\W*?\bjoin)\b|(?:f(?:\b\W*?\(\W*?\bbenchmark|null\b)|snull\b)\W*?\()|print\b\W*?\@\@|cast\b\W*?\()|c(?:(?:ur(?:rent_(?:time(?:stamp)?|date|user)|(?:dat|tim)e)|h(?:ar(?:(?:acter)?_length|set)?|r)|iel(?:ing)?|ast|r32)\W*?\(|o(?:(?:n(?:v(?:ert(?:_tz)?)?|cat(?:_ws)?|nection_id)|(?:mpres)?s|ercibility|alesce|t)\W*?\(|llation\W*?\(a))|d(?:(?:a(?:t(?:e(?:(_(add|format|sub))?|diff)|abase)|y(name|ofmonth|ofweek|ofyear)?)|e(?:(?:s_(de|en)cryp|faul)t|grees|code)|ump)\W*?\(|bms_\w+\.\b)|(?:;\W*?\b(?:shutdown|drop)|\@\@version)\b|\butl_inaddr\b|\bsys_context\b|'(?:s(?:qloledb|a)|msdasql|dbo)'))]==]) then
                waf_action_deny(waf, ctx, '32', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '37',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i)\W+\d*?\s*?having\s*?[^\s\-]]==]) then
                waf_action_deny(waf, ctx, '37', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '42',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i)(<script[^>]*>[\s\S]*?)]==]) then
                waf_action_deny(waf, ctx, '42', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '44',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i)[\s\S](?:x(?:link:href|html|mlns)|!ENTITY.*?SYSTEM|data:text\/html|pattern(?=.*?=)|formaction|\@import|base64)[\s\S]]==]) then
                waf_action_deny(waf, ctx, '44', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '45',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i)(?:<(?:(?:apple|objec)t|isindex|embed|style|form|meta)[^>]*?>[\s\S]*?|(?:=|U\s*?R\s*?L\s*?\()\s*?[^>]*?\s*?S\s*?C\s*?R\s*?I\s*?P\s*?T\s*?:)]==]) then
                waf_action_deny(waf, ctx, '45', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '48',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i)(?:\W|^)(?:javascript:(?:[\s\S]+[=\\\(\[\.<]|[\s\S]*?(?:\bname\b|\\[ux]\d))|data:(?:(?:[a-z]\w+\/\w[\w+-]+\w)?[;,]|[\s\S]*?;[\s\S]*?\b(?:base64|charset=)|[\s\S]*?,[\s\S]*?<[\s\S]*?\w[\s\S]*?>))|@\W*?i\W*?m\W*?p\W*?o\W*?r\W*?t\W*?(?:\/\*[\s\S]*?)?(?:[\"']|\W*?u\W*?r\W*?l[\s\S]*?\()|\W*?-\W*?m\W*?o\W*?z\W*?-\W*?b\W*?i\W*?n\W*?d\W*?i\W*?n\W*?g[\s\S]*?:[\s\S]*?\W*?u\W*?r\W*?l[\s\S]*?\(]==]) then
                waf_action_deny(waf, ctx, '48', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '49',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:<style.*?>.*?((@[i\\\\])|(([:=]|(&#x?0*((58)|(3A)|(61)|(3D));?)).*?([(\\\\]|(&#x?0*((40)|(28)|(92)|(5C));?)))))]==]) then
                waf_action_deny(waf, ctx, '49', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '50',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:<.*[:]vmlframe.*?[ /+\t]*?src[ /+\t]*=)]==]) then
                waf_action_deny(waf, ctx, '50', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '51',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:(j|(&#x?0*((74)|(4A)|(106)|(6A));?))([\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(a|(&#x?0*((65)|(41)|(97)|(61));?))([\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(v|(&#x?0*((86)|(56)|(118)|(76));?))([\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(a|(&#x?0*((65)|(41)|(97)|(61));?))([\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(s|(&#x?0*((83)|(53)|(115)|(73));?))([\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(c|(&#x?0*((67)|(43)|(99)|(63));?))([\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(r|(&#x?0*((82)|(52)|(114)|(72));?))([\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(i|(&#x?0*((73)|(49)|(105)|(69));?))([\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(p|(&#x?0*((80)|(50)|(112)|(70));?))([\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(t|(&#x?0*((84)|(54)|(116)|(74));?))([\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(:|(&((#x?0*((58)|(3A));?)|(colon;)))).)]==]) then
                waf_action_deny(waf, ctx, '51', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '52',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:(v|(&#x?0*((86)|(56)|(118)|(76));?))([\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(b|(&#x?0*((66)|(42)|(98)|(62));?))([\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(s|(&#x?0*((83)|(53)|(115)|(73));?))([\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(c|(&#x?0*((67)|(43)|(99)|(63));?))([\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(r|(&#x?0*((82)|(52)|(114)|(72));?))([\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(i|(&#x?0*((73)|(49)|(105)|(69));?))([\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(p|(&#x?0*((80)|(50)|(112)|(70));?))([\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(t|(&#x?0*((84)|(54)|(116)|(74));?))([\t]|(&((#x?0*(9|(13)|(10)|A|D);?)|(tab;)|(newline;))))*(:|(&((#x?0*((58)|(3A));?)|(colon;)))).)]==]) then
                waf_action_deny(waf, ctx, '52', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '53',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:<EMBED[ /+\t].*?((src)|(type)).*?=)]==]) then
                waf_action_deny(waf, ctx, '53', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '54',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:<[?]?import[ /+\t].*?implementation[ /+\t]*=)]==]) then
                waf_action_deny(waf, ctx, '54', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '55',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:<META[ /+\t].*?http-equiv[ /+\t]*=[ /+\t]*[\"\'`]?(((c|(&#x?0*((67)|(43)|(99)|(63));?)))|((r|(&#x?0*((82)|(52)|(114)|(72));?)))|((s|(&#x?0*((83)|(53)|(115)|(73));?)))))]==]) then
                waf_action_deny(waf, ctx, '55', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '56',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:<META[ /+\t].*?charset[ /+\t]*=)]==]) then
                waf_action_deny(waf, ctx, '56', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '57',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:<LINK[ /+\t].*?href[ /+\t]*=)]==]) then
                waf_action_deny(waf, ctx, '57', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '58',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:<BASE[ /+\t].*?href[ /+\t]*=)]==]) then
                waf_action_deny(waf, ctx, '58', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '59',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i:<APPLET[ /+\t>])]==]) then
                waf_action_deny(waf, ctx, '59', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '60',  false ,  t._1, 't._1', v._2, 'v_2', [==[(?i:<OBJECT[ /+\t].*?((type)|(codetype)|(classid)|(code)|(data))[ /+\t]*=)]==]) then
                waf_action_deny(waf, ctx, '60', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '61',  false ,  t._2, 't._2', v._2, 'v_2', [==[.*¾.*¼.*|.*¼.*¾.*]==]) then
                waf_action_deny(waf, ctx, '61', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '63',  false ,  t._3, 't._3', v._2, 'v_2', [==[(?i:[\"\'][ ]*(([^a-z0-9~_:\' ])|(in)).*?(((l|(\\\\u006C))(o|(\\\\u006F))(c|(\\\\u0063))(a|(\\\\u0061))(t|(\\\\u0074))(i|(\\\\u0069))(o|(\\\\u006F))(n|(\\\\u006E)))|((n|(\\\\u006E))(a|(\\\\u0061))(m|(\\\\u006D))(e|(\\\\u0065)))|((o|(\\\\u006F))(n|(\\\\u006E))(e|(\\\\u0065))(r|(\\\\u0072))(r|(\\\\u0072))(o|(\\\\u006F))(r|(\\\\u0072)))|((v|(\\\\u0076))(a|(\\\\u0061))(l|(\\\\u006C))(u|(\\\\u0075))(e|(\\\\u0065))(O|(\\\\u004F))(f|(\\\\u0066)))).*?=)]==]) then
                waf_action_deny(waf, ctx, '63', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '65',  false ,  t._3, 't._3', v._2, 'v_2', [==[(?i:[\"\'][ ]*(([^a-z0-9~_:\' ])|(in)).+?[.].+?=)]==]) then
                waf_action_deny(waf, ctx, '65', [==[null]==])
                return
            end
                    if waf_operator_pmFromFile(waf, ctx, '67]',  false , t._0, 't._0', v._2, 'v_2', [==[sql-function-names.data]==]) and
                waf_operator_rx(waf, ctx, '67',  false ,  t._0, 't._0', v._3, 'v_3', [==[(?i)\b(?:c(?:o(?:n(?:v(?:ert(?:_tz)?)?|cat(?:_ws)?|nection_id)|(?:mpres)?s|ercibility|(?:un)?t|llation|alesce)|ur(?:rent_(?:time(?:stamp)?|date|user)|(?:dat|tim)e)|h(?:ar(?:(?:acter)?_length|set)?|r)|iel(?:ing)?|ast|r32)|s(?:u(?:b(?:str(?:ing(?:_index)?)?|(?:dat|tim)e)|m)|t(?:d(?:dev_(?:sam|po)p)?|r(?:_to_date|cmp))|e(?:c(?:_to_time|ond)|ssion_user)|ys(?:tem_user|date)|ha[12]?|oundex|chema|ig?n|leep|pace|qrt)|i(?:s(?:_(?:ipv(?:4(?:_(?:compat|mapped))?|6)|n(?:ot(?:_null)?|ull)|(?:free|used)_lock)|null)|n(?:et(?:6_(?:aton|ntoa)|_(?:aton|ntoa))|s(?:ert|tr)|terval)?|f(?:null)?)|d(?:a(?:t(?:e(?:_(?:format|add|sub)|diff)?|abase)|y(?:of(?:month|week|year)|name)?)|e(?:(?:s_(?:de|en)cryp|faul)t|grees|code)|count|ump)|l(?:o(?:ca(?:l(?:timestamp)?|te)|g(?:10|2)?|ad_file|wer)|ast(?:_(?:inser_id|day))?|e(?:(?:as|f)t|ngth)|case|trim|pad|n)|u(?:n(?:compress(?:ed_length)?|ix_timestamp|hex)|tc_(?:time(?:stamp)?|date)|p(?:datexml|per)|uid(?:_short)?|case|ser)|t(?:ime(?:_(?:format|to_sec)|stamp(?:diff|add)?|diff)?|o(?:(?:second|day)s|_base64|n?char)|r(?:uncate|im)|an)|m(?:a(?:ke(?:_set|date)|ster_pos_wait|x)|i(?:(?:crosecon)?d|n(?:ute)?)|o(?:nth(?:name)?|d)|d5)|r(?:e(?:p(?:lace|eat)|lease_lock|verse)|a(?:wtohex|dians|nd)|o(?:w_count|und)|ight|trim|pad)|f(?:i(?:eld(?:_in_set)?|nd_in_set)|rom_(?:unixtime|base64|days)|o(?:und_rows|rmat)|loor)|p(?:o(?:w(?:er)?|sition)|eriod_(?:diff|add)|rocedure_analyse|assword|g_sleep|i)|a(?:s(?:cii(?:str)?|in)|es_(?:de|en)crypt|dd(?:dat|tim)e|(?:co|b)s|tan2?|vg)|b(?:i(?:t_(?:length|count|x?or|and)|n(?:_to_num)?)|enchmark)|e(?:x(?:tract(?:value)?|p(?:ort_set)?)|nc(?:rypt|ode)|lt)|g(?:r(?:oup_conca|eates)t|et_(?:format|lock))|v(?:a(?:r(?:_(?:sam|po)p|iance)|lues)|ersion)|o(?:(?:ld_passwo)?rd|ct(?:et_length)?)|we(?:ek(?:ofyear|day)?|ight_string)|n(?:o(?:t_in|w)|ame_const|ullif)|h(?:ex(?:toraw)?|our)|qu(?:arter|ote)|year(?:week)?|xmltype)\W*\(]==]) then
                waf_action_deny(waf, ctx, '67', [==[null]==])
                return
            end
                    if waf_operator_pm(waf, ctx, '68',  false ,  t._0, 't._0', v._2, 'v_2', [==[document.cookie document.write .parentnode .innerhtml window.location -moz-binding <!-- --> <![cdata[]==]) then
                waf_action_deny(waf, ctx, '68', [==[null]==])
                return
            end
                    if waf_operator_pm(waf, ctx, '69',  false ,  t._4, 't._4', v._2, 'v_2', [==[<? <?php ?> [php] [\php]]==]) then
                waf_action_deny(waf, ctx, '69', [==[null]==])
                return
            end
                    if waf_operator_pmFromFile(waf, ctx, '70',  false ,  t._0, 't._0', v._2, 'v_2', [==[php-config-directives.data]==]) then
                waf_action_deny(waf, ctx, '70', [==[null]==])
                return
            end
                    if waf_operator_pmFromFile(waf, ctx, '71',  false ,  t._0, 't._0', v._2, 'v_2', [==[php-variables.data]==]) then
                waf_action_deny(waf, ctx, '71', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '72',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i)php://(std(in|out|err)|(in|out)put|fd|memory|temp|filter)]==]) then
                waf_action_deny(waf, ctx, '72', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '73',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i)\b(?:s(?:e(?:t_(?:e(?:xception|rror)_handler|magic_quotes_runtime|include_path)|ssion_start)|qlite_(?:(?:(?:unbuffered|single|array)_)?query|p?open|exec)|tr(?:eam_(?:context_create|socket_client)|ipc?slashes|rev)|implexml_load_(?:string|file)|ocket_c(?:onnect|reate)|ystem)|p(?:r(?:eg_(?:replace(?:_callback(?:_array)?)?|match(?:_all)?|split)|oc_open|int_r)|o(?:six_(?:get(?:(?:e[gu]|g)id|login|pwnam)|mknod)|pen)|g_(?:(?:execut|prepar)e|connect|query)|hp(?:version|_uname|info)|assthru|utenv)|o(?:b_(?:get_(?:c(?:ontents|lean)|flush)|end_(?:clean|flush)|clean|flush|start)|dbc_(?:result(?:_all)?|exec(?:ute)?|connect)|pendir)|m(?:b_ereg(?:_(?:replace(?:_callback)?|match)|i(?:_replace)?)?|ove_uploaded_file|ethod_exists|ysql_query|kdir)|g(?:z(?:(?:(?:defla|wri)t|encod|fil)e|compress|open|read)|et(?:(?:myui|cw)d|env))|f(?:i(?:le(?:_exists)?|nfo_open)|(?:unction_exis|pu)ts|tp_connect|write|open)|i(?:s_(?:(?:(?:execut|write?|read)ab|fi)le|dir)|ni_(?:get(?:_all)?|set))|h(?:tml(?:specialchars(?:_decode)?|_entity_decode|entities)|ex2bin)|e(?:scapeshell(?:arg|cmd)|rror_reporting|val|xec)|r(?:ead(?:(?:gz)?file|dir)|awurl(?:de|en)code)|b(?:(?:son_(?:de|en)|ase64_en)code|zopen)|c(?:url_(?:exec|init)|onvert_uuencode|hr)|u(?:n(?:serialize|pack)|rl(?:de|en)code)|(?:json_(?:de|en)cod|debug_backtrac)e|var_dump)(?:\s|/\*.*\*/|//.*|#.*)*\(.*\)]==]) then
                waf_action_deny(waf, ctx, '73', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '74',  false ,  t._0, 't._0', v._2, 'v_2', [==[[oOcC]:\d+:\".+?\":\d+:{.*}]==]) then
                waf_action_deny(waf, ctx, '74', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '75',  false ,  t._0, 't._0', v._2, 'v_2', [==[\$+(?:[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*|\s*{.+})(?:\s|\[.+\]|{.+}|/\*.*\*/|//.*|#.*)*\(.*\)]==]) then
                waf_action_deny(waf, ctx, '75', [==[null]==])
                return
            end
                    if waf_operator_pmFromFile(waf, ctx, '76',  false ,  t._0, 't._0', v._2, 'v_2', [==[php-function-names-933151.data]==]) then
                waf_action_deny(waf, ctx, '76', [==[null]==])
                return
            end
                    if waf_operator_rx(waf, ctx, '77',  false ,  t._0, 't._0', v._2, 'v_2', [==[(?i)\b(?:i(?:s(?:_(?:in(?:t(?:eger)?|finite)|n(?:u(?:meric|ll)|an)|(?:calla|dou)ble|s(?:calar|tring)|f(?:inite|loat)|re(?:source|al)|l(?:ink|ong)|a(?:rray)?|object|bool)|set)|(?:mplod|dat)e|nt(?:div|val)|conv)|s(?:t(?:r(?:(?:le|sp)n|coll)|at)|(?:e(?:rializ|ttyp)|huffl)e|i(?:milar_text|zeof|nh?)|p(?:liti?|rintf)|(?:candi|ubst)r|y(?:mlink|slog)|o(?:undex|rt)|leep|rand|qrt)|c(?:h(?:o(?:wn|p)|eckdate|root|dir|mod)|o(?:(?:(?:nsta|u)n|mpac)t|sh?|py)|lose(?:dir|log)|(?:urren|ryp)t|eil)|f(?:ile(?:(?:siz|typ)e|owner|pro)|l(?:o(?:atval|ck|or)|ush)|(?:rea|mo)d|t(?:ell|ok)|close|gets|stat|eof)|e(?:x(?:(?:trac|i)t|p(?:lode)?)|a(?:ster_da(?:te|ys)|ch)|r(?:ror_log|egi?)|mpty|cho|nd)|l(?:o(?:g(?:1[0p])?|caltime)|i(?:nk(?:info)?|st)|(?:cfirs|sta)t|evenshtein|trim)|d(?:i(?:(?:skfreespac)?e|r(?:name)?)|e(?:fined?|coct)|(?:oubleva)?l|ate)|m(?:b(?:split|ereg)|i(?:crotime|n)|a(?:i[ln]|x)|etaphone|y?sql|hash)|r(?:e(?:(?:cod|nam)e|adlin[ek]|wind|set)|an(?:ge|d)|ound|sort|trim)|t(?:e(?:xtdomain|mpnam)|(?:mpfil|im)e|a(?:int|nh?)|ouch|rim)|u(?:n(?:(?:tain|se)t|iqid|link)|s(?:leep|ort)|cfirst|mask)|a(?:s(?:(?:se|o)rt|inh?)|r(?:sort|ray)|tan[2h]?|cosh?|bs)|h(?:e(?:ader(?:s_(?:lis|sen)t)?|brev)|ypot|ash)|p(?:a(?:thinfo|ck)|r(?:intf?|ev)|close|o[sw]|i)|g(?:et(?:t(?:ext|ype)|date)|mdate|lob)|o(?:penlog|ctdec|rd)|b(?:asename|indec)|n(?:atsor|ex)t|k(?:sort|ey)|quotemeta|wordwrap|virtual|join)(?:\s|/\*.*\*/|//.*|#.*)*\(.*\)]==]) then
                waf_action_deny(waf, ctx, '77', [==[null]==])
                return
            end
                    if waf_operator_pmFromFile(waf, ctx, '79',  false ,  t._0, 't._0', v._2, 'v_2', [==[scanners-urls.data]==]) then
                waf_action_deny(waf, ctx, '79', [==[null]==])
                return
            end
        
    elseif phase == "header_filter" then

    elseif phase == "body_filter" then

    end
end

return _M