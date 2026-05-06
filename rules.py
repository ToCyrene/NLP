# rules.py
from rules_generated import GENERATED_RULES
# --- 1. AST 深度分析配置 (Python 专用) ---
# 这部分用于 analyzer.py 中的 AST 访问器
AST_RULES_CONFIG = {
    "Python": {
        "BANNED_FUNCTIONS": {
            # Code Injection
            "eval": {"level": "Critical", "message": "代码注入风险: eval()", "category": "Code Injection"},
            "exec": {"level": "Critical", "message": "代码注入风险: exec()", "category": "Code Injection"},
            "execfile": {"level": "Critical", "message": "代码注入风险: execfile()", "category": "Code Injection"},
            "compile": {"level": "Warning", "message": "代码注入风险: compile()", "category": "Code Injection"},
            
            # Command Injection
            "os.system": {"level": "Critical", "message": "命令注入风险: os.system()", "category": "Command Injection"},
            "os.popen": {"level": "Critical", "message": "命令注入风险: os.popen()", "category": "Command Injection"},
            "os.spawn": {"level": "Critical", "message": "命令注入风险: os.spawn()", "category": "Command Injection"},
            "subprocess.call": {"level": "Warning", "message": "命令执行: 检查 shell=True", "category": "Command Injection"},
            "subprocess.check_output": {"level": "Warning", "message": "命令执行", "category": "Command Injection"},
            "subprocess.run": {"level": "Warning", "message": "命令执行", "category": "Command Injection"},
            "commands.getoutput": {"level": "Critical", "message": "命令注入: commands 模块 (Python 2)", "category": "Command Injection"},
            "commands.getstatusoutput": {"level": "Critical", "message": "命令注入: commands 模块", "category": "Command Injection"},
            
            # Deserialization
            "pickle.loads": {"level": "Error", "message": "反序列化风险: pickle", "category": "Deserialization"},
            "yaml.load": {"level": "Error", "message": "反序列化风险: 建议 safe_load", "category": "Deserialization"},
            "marshal.load": {"level": "Error", "message": "反序列化风险: marshal", "category": "Deserialization"},
            "shelve.open": {"level": "Warning", "message": "反序列化风险: shelve", "category": "Deserialization"},
            
            # Path Traversal & File
            "open": {"level": "Info", "message": "文件操作: 检查路径是否受控", "category": "File Access"},
            "tarfile.open": {"level": "Warning", "message": "ZipSlip 风险: 检查解压路径", "category": "Path Traversal"},
            "zipfile.ZipFile": {"level": "Warning", "message": "ZipSlip 风险", "category": "Path Traversal"},
            
            # XXE
            "lxml.etree.parse": {"level": "Error", "message": "XXE 风险: 检查 XML 解析配置", "category": "XXE"},
            "xml.sax.parse": {"level": "Warning", "message": "XXE 风险", "category": "XXE"},
        },
        "TAINT_SOURCES": {
            # Standard Input
            "input": "Console Input",
            "raw_input": "Console Input (Py2)",
            "sys.argv": "CLI Args",
            "sys.stdin": "Standard Input",
            
            # Flask / Web
            "request.args.get": "Web Param",
            "flask.request.args.get": "Web Param",
            "request.form.get": "Web Form Data",
            "flask.request.form.get": "Web Form Data",
            "request.values.get": "Web Request Data",
            "flask.request.values.get": "Web Request Data",
            "request.json": "JSON Body",
            "request.data": "Raw Body",
            "request.cookies": "Cookies",
            "request.headers": "Headers",
            
            # Django
            "request.GET": "Django GET",
            "request.POST": "Django POST",
            "request.body": "Django Body",
            
            # Environment
            "os.environ": "Environment Variable",
            "os.getenv": "Environment Variable",
        },
        "SANITIZERS": {
            "shlex.quote": "Shell Escape",
            "html.escape": "HTML Escape",
            "int": "Type Cast",
            "float": "Type Cast",
            "bool": "Type Cast",
            "str": "String Cast", 
            "json.dumps": "JSON Encode",
            "werkzeug.utils.secure_filename": "Filename Sanitization"
        },
        "HARDCODED_SECRETS": {
            "keywords": ["password", "secret", "token", "key", "auth", "passwd", "api_key", "access_key", "credentials", "jwt_secret"],
            "level": "Critical",
            "message": "硬编码凭证",
            "category": "Hardcoded Secret"
        }
    }
}

# --- 2. 正则兜底规则 (Manual Regex Rules) ---
# 这些规则用于 analyzer.py 中的正则扫描部分，覆盖所有语言
MANUAL_RULES = {
    "Python": [
        # Injection
        {"id": "PY_CMD_RE", "pattern": r"(os\.system|os\.popen|commands\.getoutput|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(", "level": "Critical", "category": "Command Injection", "message": "命令注入风险 (Regex)"},
        {"id": "PY_CODE_RE", "pattern": r"\b(eval|exec|execfile)\s*\(", "level": "Critical", "category": "Code Injection", "message": "代码注入风险 (Regex)"},
        {"id": "PY_SQLI_RE", "pattern": r"(execute|cursor)\s*\(\s*[\"'].*?%s.*?[\"']\s*%", "level": "Error", "category": "SQL Injection", "message": "SQL注入 (字符串拼接 %s)"},
        {"id": "PY_SQLI_FMT", "pattern": r"(execute|cursor)\s*\(\s*f[\"'].*?\{.*?\}.*?[\"']", "level": "Error", "category": "SQL Injection", "message": "SQL注入 (f-string 拼接)"},
        
        # Deserialization
        {"id": "PY_PICKLE_RE", "pattern": r"\b(pickle|cPickle)\.loads\s*\(", "level": "Error", "category": "Deserialization", "message": "反序列化风险 (pickle)"},
        {"id": "PY_YAML_RE", "pattern": r"\byaml\.load\s*\(", "level": "Error", "category": "Deserialization", "message": "反序列化风险 (使用 safe_load)"},
        
        # Web / SSRF
        {"id": "PY_SSRF_REQ", "pattern": r"\brequests\.(get|post|put|delete|head)\s*\(\s*request\.", "level": "Warning", "category": "SSRF", "message": "潜在的 SSRF: 请求目标直接来自用户输入"},
        {"id": "PY_SSRF_URLOPEN", "pattern": r"urllib\.request\.urlopen\s*\(\s*request\.", "level": "Warning", "category": "SSRF", "message": "潜在的 SSRF: urlopen"},

        # Misc
        {"id": "PY_TEMP_FILE", "pattern": r"\bmktemp\s*\(", "level": "Warning", "category": "Insecure Temp File", "message": "不安全的临时文件创建 (使用 mkstemp)"},
        {"id": "PY_DEBUG_TRUE", "pattern": r"debug\s*=\s*True", "level": "Info", "category": "Configuration", "message": "Debug 模式开启 (生产环境请关闭)"},
        {"id": "PY_BIND_ALL", "pattern": r"\.bind\s*\(\s*\(['\"]0\.0\.0\.0['\"]", "level": "Warning", "category": "Network Exposure", "message": "监听 0.0.0.0 (全网公开)"},
    ],
    
    "C/C++": [
        # Buffer Overflow - Dangerous Functions
        {"id": "CPP_BUF_CPY", "pattern": r"\b(strcpy|wcscpy|stpcpy)\s*\(", "level": "Critical", "category": "Buffer Overflow", "message": "不安全函数: strcpy (建议 strncpy)"},
        {"id": "CPP_BUF_CAT", "pattern": r"\b(strcat|wcscat)\s*\(", "level": "Critical", "category": "Buffer Overflow", "message": "不安全函数: strcat (建议 strncat)"},
        {"id": "CPP_BUF_SPR", "pattern": r"\b(sprintf|vsprintf)\s*\(", "level": "Critical", "category": "Buffer Overflow", "message": "不安全函数: sprintf (建议 snprintf)"},
        {"id": "CPP_BUF_GETS", "pattern": r"\bgets\s*\(", "level": "Critical", "category": "Buffer Overflow", "message": "已被废弃且极其危险: gets (无边界检查)"},
        {"id": "CPP_BUF_SCANF", "pattern": r"\bscanf\s*\(\s*\"%s\"", "level": "Error", "category": "Buffer Overflow", "message": "scanf \"%s\" 无宽度限制"},
        
        # Command Injection
        {"id": "CPP_CMD_SYS", "pattern": r"\bsystem\s*\(", "level": "Critical", "category": "Command Injection", "message": "命令执行: system"},
        {"id": "CPP_CMD_POPEN", "pattern": r"\bpopen\s*\(", "level": "Critical", "category": "Command Injection", "message": "命令执行: popen"},
        {"id": "CPP_EXEC", "pattern": r"\bexec(l|v|le|ve|lp|vp)\s*\(", "level": "Critical", "category": "Command Injection", "message": "进程执行: exec 系列"},
        
        # Format String
        {"id": "CPP_FMT", "pattern": r"\b(printf|syslog|fprintf)\s*\([^,]*\);", "level": "Error", "category": "Format String", "message": "格式化字符串漏洞: 缺少格式化参数"},
        
        # Misc
        {"id": "CPP_RAND", "pattern": r"\brand\s*\(", "level": "Info", "category": "Weak PRNG", "message": "弱伪随机数生成器 (使用 rand)"},
        {"id": "CPP_CHMOD", "pattern": r"\bchmod\s*\(.*0777", "level": "Warning", "category": "Insecure Permissions", "message": "不安全的文件权限 (0777)"},
    ],
    
    "Java": [
        # Injection
        {"id": "JV_CMD_EXEC", "pattern": r"(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(", "level": "Critical", "category": "Command Injection", "message": "命令执行风险"},
        {"id": "JV_SQL_CONCAT", "pattern": r"(executeQuery|executeUpdate)\s*\(\s*[\"].*[\"]\s*\+", "level": "Warning", "category": "SQL Injection", "message": "SQL注入: 检测到字符串拼接"},
        
        # Deserialization
        {"id": "JV_DESER_READOBJ", "pattern": r"readObject\s*\(", "level": "Warning", "category": "Deserialization", "message": "反序列化: readObject (需人工审查)"},
        {"id": "JV_XSTREAM", "pattern": r"new\s+XStream\s*\(", "level": "Warning", "category": "Deserialization", "message": "XStream 反序列化风险"},
        
        # XXE
        {"id": "JV_XXE_BUILDER", "pattern": r"DocumentBuilderFactory\.newInstance\s*\(", "level": "Warning", "category": "XXE", "message": "XML解析: 需禁用外部实体 (XXE)"},
        {"id": "JV_XXE_SAX", "pattern": r"SAXParserFactory\.newInstance\s*\(", "level": "Warning", "category": "XXE", "message": "XML解析: SAXParser (XXE)"},
        
        # Cryptography
        {"id": "JV_WEAK_HASH", "pattern": r"MessageDigest\.getInstance\s*\(\"(MD5|SHA-1)\"\)", "level": "Warning", "category": "Weak Cryptography", "message": "弱哈希算法 (MD5/SHA1)"},
        {"id": "JV_WEAK_CIPHER", "pattern": r"Cipher\.getInstance\s*\(\"DES\"", "level": "Error", "category": "Weak Cryptography", "message": "过时的加密算法 (DES)"},
        {"id": "JV_ECB_MODE", "pattern": r"Cipher\.getInstance\s*\(\".*/ECB/.*\"\)", "level": "Error", "category": "Weak Cryptography", "message": "不安全的加密模式: ECB"},
        
        # Hardcoded Secrets
        {"id": "JV_AWS_KEY", "pattern": r"(AKIA|ASIA)[0-9A-Z]{16}", "level": "Critical", "category": "Hardcoded Secret", "message": "检测到 AWS Access Key"},
    ],
    
    "JavaScript/TypeScript": [
        # Code / Command Injection
        {"id": "JS_EVAL", "pattern": r"\beval\s*\(", "level": "Critical", "category": "Code Injection", "message": "危险函数: eval"},
        {"id": "JS_SET_TIMEOUT", "pattern": r"(setTimeout|setInterval)\s*\(\s*[\'\"]", "level": "Warning", "category": "Code Injection", "message": "定时器传入字符串代码 (Implied eval)"},
        {"id": "JS_EXEC", "pattern": r"(child_process|cp)\.exec(Sync)?\s*\(", "level": "Critical", "category": "Command Injection", "message": "Node.js 命令执行"},
        {"id": "JS_SPAWN", "pattern": r"(child_process|cp)\.spawn(Sync)?\s*\(", "level": "Warning", "category": "Command Injection", "message": "Node.js 进程启动"},
        
        # XSS
        {"id": "JS_DOC_WRITE", "pattern": r"document\.write(ln)?\s*\(", "level": "Error", "category": "XSS", "message": "DOM XSS: document.write"},
        {"id": "JS_INNERHTML", "pattern": r"\.innerHTML\s*=", "level": "Warning", "category": "XSS", "message": "DOM XSS: innerHTML 赋值"},
        {"id": "JS_OUTERHTML", "pattern": r"\.outerHTML\s*=", "level": "Warning", "category": "XSS", "message": "DOM XSS: outerHTML 赋值"},
        {"id": "JS_DANGEROUS_HTML", "pattern": r"dangerouslySetInnerHTML", "level": "Warning", "category": "XSS", "message": "React XSS 风险"},
        {"id": "JS_SCE", "pattern": r"\$sce\.trustAsHtml", "level": "Warning", "category": "XSS", "message": "AngularJS SCE (需审查来源)"},
        
        # Crypto
        {"id": "JS_MATH_RANDOM", "pattern": r"Math\.random\s*\(", "level": "Info", "category": "Weak PRNG", "message": "弱伪随机数 (加密场景请用 crypto.getRandomValues)"},
        
        # NoSQL Injection
        {"id": "JS_NOSQL_WHERE", "pattern": r"\$where\s*:", "level": "Error", "category": "NoSQL Injection", "message": "MongoDB $where 注入风险"},
    ],
    
    "Go": [
        # Injection
        {"id": "GO_SQL_FMT", "pattern": r"(fmt\.Sprintf|WriteString)\s*\(.*(select|insert|update|delete).*from", "level": "Error", "category": "SQL Injection", "message": "SQL注入: 拼接构建 SQL"},
        {"id": "GO_CMD_EXEC", "pattern": r"exec\.Command(Context)?\s*\(", "level": "Warning", "category": "Command Injection", "message": "命令执行"},
        
        # Memory Safety
        {"id": "GO_UNSAFE", "pattern": r"unsafe\.Pointer\s*\(", "level": "Warning", "category": "Memory Safety", "message": "使用 unsafe 包"},
        
        # XSS
        {"id": "GO_HTML_TEMPLATE", "pattern": r"template\.HTML\s*\(", "level": "Warning", "category": "XSS", "message": "Go Template: 标记字符串为安全 HTML"},
        
        # Crypto
        {"id": "GO_WEAK_MD5", "pattern": r"md5\.New\s*\(", "level": "Warning", "category": "Weak Cryptography", "message": "弱哈希算法: MD5"},
        {"id": "GO_WEAK_RC4", "pattern": r"rc4\.NewCipher", "level": "Error", "category": "Weak Cryptography", "message": "过时的流加密: RC4"},
    ],
    
    "PHP": [
        {"id": "PHP_EXEC", "pattern": r"\b(system|exec|passthru|shell_exec|popen|proc_open)\s*\(", "level": "Critical", "category": "Command Injection", "message": "PHP 命令执行函数"},
        {"id": "PHP_EVAL", "pattern": r"\b(eval|assert)\s*\(", "level": "Critical", "category": "Code Injection", "message": "PHP 代码注入"},
        {"id": "PHP_INCLUDE", "pattern": r"\b(include|require)(_once)?\s*\(?\s*\$", "level": "Warning", "category": "File Inclusion", "message": "动态文件包含 (LFI/RFI)"},
        {"id": "PHP_UNSERIALIZE", "pattern": r"\bunserialize\s*\(", "level": "Error", "category": "Deserialization", "message": "反序列化漏洞"},
        {"id": "PHP_SQLI", "pattern": r"(mysql_query|mysqli_query)\s*\(\s*[\"'].*?\$", "level": "Warning", "category": "SQL Injection", "message": "老旧 MySQL 扩展 / 拼接 SQL"},
    ],
    
    "C#": [
        {"id": "CS_SQLI", "pattern": r"(SqlCommand|OleDbCommand|OdbcCommand)\s*\(\s*[\"'].*\+", "level": "Warning", "category": "SQL Injection", "message": "SQL注入: 拼接 SQL 语句"},
        {"id": "CS_CMD", "pattern": r"Process\.Start\s*\(", "level": "Warning", "category": "Command Injection", "message": "进程启动: Process.Start"},
        {"id": "CS_DESER", "pattern": r"(BinaryFormatter|SoapFormatter|LosFormatter)", "level": "Critical", "category": "Deserialization", "message": "不安全的反序列化器"},
        {"id": "CS_XXE", "pattern": r"XmlDocument\s*\(\)\s*;", "level": "Info", "category": "XXE", "message": "XmlDocument: 默认可能解析 DTD，需检查设置"},
    ]
}

# --- 3. 规则合并逻辑 ---
# 先加载手动规则，再追加自动挖掘的规则
RULES_DB = MANUAL_RULES.copy()

if isinstance(GENERATED_RULES, dict):
    for lang, mined_rules in GENERATED_RULES.items():
        if lang not in RULES_DB:
            RULES_DB[lang] = []
        # 将自动生成的规则追加到手动规则之后
        RULES_DB[lang].extend(mined_rules)
        
# 确保所有支持的语言都在 DB 中有 key
SUPPORTED_LANGS = ["Python", "JavaScript/TypeScript", "Java", "C/C++", "Go", "PHP", "C#"]
for lang in SUPPORTED_LANGS:
    if lang not in RULES_DB:
        RULES_DB[lang] = []