# analyzer.py
import re
import ast
import math
from rules import RULES_DB, AST_RULES_CONFIG

class CodeIssue:
    def __init__(self, line_no, content, rule_id, level, message, category):
        self.line_no = line_no
        self.content = content.strip()
        self.rule_id = rule_id
        self.level = level
        self.message = message
        self.category = category
    
    def __repr__(self):
        return f"[{self.level}] Line {self.line_no}: {self.message}"

def remove_comments(code, language):
    def replacer(match):
        s = match.group(0)
        if s.startswith('/'): return " "
        if s.startswith('#'): return " "
        return s
    
    if language == "Python":
        pattern = re.compile(r'(\".*?\"|\'.*?\')|(#.*)')
    else:
        pattern = re.compile(r'(\".*?\"|\'.*?\')|(//.*?$|/\*.*?\*/)', re.DOTALL | re.MULTILINE)
    try:
        return re.sub(pattern, replacer, code)
    except:
        return code

def get_full_name(node):
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        value = get_full_name(node.value)
        if value:
            return f"{value}.{node.attr}"
    return None

def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

class PreAnalysisVisitor(ast.NodeVisitor):
    def __init__(self):
        self.config = AST_RULES_CONFIG.get("Python", {})
        self.custom_sinks = {}
        self.custom_sources = set()
        self.current_func_name = None
        self.current_func_args = set()
        self.current_func_returns_taint = False

    def visit_FunctionDef(self, node):
        self.current_func_name = node.name
        self.current_func_args = {arg.arg for arg in node.args.args}
        self.current_func_returns_taint = False
        self.generic_visit(node)
        if self.current_func_returns_taint:
            self.custom_sources.add(self.current_func_name)
        self.current_func_name = None
        self.current_func_args = set()

    def visit_Call(self, node):
        if not self.current_func_name: return
        func_name = get_full_name(node.func)
        banned = self.config.get("BANNED_FUNCTIONS", {})
        if func_name and func_name in banned:
            if node.args:
                first_arg = node.args[0]
                arg_name = None
                if isinstance(first_arg, ast.Name):
                    arg_name = first_arg.id
                if arg_name and arg_name in self.current_func_args:
                    self.custom_sinks[self.current_func_name] = func_name
        self.generic_visit(node)

    def visit_Return(self, node):
        if node.value and isinstance(node.value, ast.Call):
            func_name = get_full_name(node.value.func)
            sources = self.config.get("TAINT_SOURCES", {})
            for source_key in sources:
                if func_name and func_name.endswith(source_key):
                    self.current_func_returns_taint = True
                    break
        self.generic_visit(node)

class PythonTaintVisitor(ast.NodeVisitor):
    def __init__(self, code_lines, custom_sinks=None, custom_sources=None):
        self.issues = []
        self.code_lines = code_lines
        self.config = AST_RULES_CONFIG.get("Python", {})
        self.tainted_vars = {} 
        self.custom_sinks = custom_sinks if custom_sinks else {}
        self.custom_sources = custom_sources if custom_sources else set()

    def _add_issue(self, node, rule_id, level, message, category):
        line_no = node.lineno
        if 0 < line_no <= len(self.code_lines):
            content = self.code_lines[line_no - 1]
            self.issues.append(CodeIssue(line_no, content, rule_id, level, message, category))

    def _get_name(self, node):
        return get_full_name(node)

    def _is_safe_expression(self, node):
        if isinstance(node, (ast.Constant, ast.Str, ast.Num)): return True
        if isinstance(node, ast.Name): return node.id not in self.tainted_vars
        if isinstance(node, ast.BinOp): return self._is_safe_expression(node.left) and self._is_safe_expression(node.right)
        return False

    def visit_FunctionDef(self, node):
        old_taint = self.tainted_vars.copy()
        self.tainted_vars = {} 
        self.generic_visit(node)
        self.tainted_vars = old_taint

    def _contains_taint(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        elif isinstance(node, ast.BinOp):
            return self._contains_taint(node.left) or self._contains_taint(node.right)
        elif isinstance(node, ast.JoinedStr): # f-string
            return any(self._contains_taint(val) for val in node.values)
        elif isinstance(node, ast.FormattedValue):
            return self._contains_taint(node.value)
        return False

    def visit_Assign(self, node):
        source_description = None
        is_cleaned = False
        
        # 1. 函数调用
        if isinstance(node.value, ast.Call):
            func_name = get_full_name(node.value.func)
            sources = self.config.get("TAINT_SOURCES", {})
            
            # 检测 Source
            for source_key, desc in sources.items():
                if func_name and func_name.endswith(source_key):
                    source_description = desc
                    break
            if func_name in self.custom_sources:
                source_description = f"Custom Source ({func_name})"
            
            # 检测 Sanitizer
            sanitizers = self.config.get("SANITIZERS", {})
            if func_name in sanitizers:
                is_cleaned = True
            
            if not is_cleaned and not source_description:
                for arg in node.value.args:
                    if self._contains_taint(arg):
                        source_description = "Propagated Taint"
                        break
        
        # 2. 变量赋值 / 运算 / 字符串拼接
        elif self._contains_taint(node.value):
             source_description = "Propagated Taint"

        # 更新左值
        for target in node.targets:
            target_name = self._get_name(target)
            if target_name:
                if is_cleaned:
                    if target_name in self.tainted_vars:
                        del self.tainted_vars[target_name]
                elif source_description:
                    self.tainted_vars[target_name] = source_description
                else:
                    if isinstance(node.value, (ast.Constant, ast.Str, ast.Num)):
                         if target_name in self.tainted_vars:
                            del self.tainted_vars[target_name]
                            
        self._check_hardcoded_secrets(node)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        target_name = self._get_name(node.target)
        if target_name and self._contains_taint(node.value):
             self.tainted_vars[target_name] = "Propagated via AugAssign"
        self.generic_visit(node)

    def _check_hardcoded_secrets(self, node):
        secrets_config = self.config.get("HARDCODED_SECRETS", {})
        keywords = secrets_config.get("keywords", [])
        
        val = None
        if isinstance(node.value, ast.Constant): val = node.value.value
        elif isinstance(node.value, ast.Str): val = node.value.s
        
        if not isinstance(val, str) or len(val) < 8: return

        for target in node.targets:
            target_name = self._get_name(target)
            if not target_name: continue
            
            is_suspicious_name = any(k in target_name.lower() for k in keywords)
            entropy = calculate_entropy(val)
            
            if is_suspicious_name:
                if entropy > 3.8 or (len(val) > 20 and entropy > 3.0):
                    msg = f"检测到硬编码敏感信息 (Entropy: {entropy:.2f})"
                    self._add_issue(node, "AST_SECRET", "Critical", msg, "Hardcoded Secret")
            
            if val.startswith("sk-") and len(val) > 20:
                 self._add_issue(node, "AST_SECRET_KEY", "Critical", "疑似 OpenAI API Key", "Hardcoded Secret")

    def visit_Call(self, node):
        func_name = get_full_name(node.func)
        banned = self.config.get("BANNED_FUNCTIONS", {})
        
        is_standard_sink = func_name and func_name in banned
        is_custom_sink = func_name and func_name in self.custom_sinks

        if is_standard_sink or is_custom_sink:
            if is_standard_sink:
                info = banned[func_name]
                risk_msg = info['message']
            else:
                original_sink = self.custom_sinks[func_name]
                info = banned.get(original_sink, {"level": "Critical", "category": "Injection"})
                risk_msg = f"调用了危险包装函数 '{func_name}' (wrap {original_sink})"

            risk_level = info['level']
            category = info['category']
            
            if node.args:
                first_arg = node.args[0]
                arg_name = self._get_name(first_arg)

                if self._is_safe_expression(first_arg):
                    risk_level = "Warning"
                    risk_msg += " (参数看似安全)"
                elif self._contains_taint(first_arg): # 使用增强的检查
                    risk_level = "Critical"
                    risk_msg += f" [确认: 污染源 -> 未清洗]"
                else:
                    risk_level = "Error"
                    risk_msg += " (参数来源不明)"

            rule_id = f"AST_SINK_{str(func_name).upper().replace('.', '_')}"
            self._add_issue(node, rule_id, risk_level, risk_msg, category)
        
        self.generic_visit(node)

def analyze_code_generic(code_text, language):
    issues = []
    lines = code_text.split('\n')
    
    # 1. AST 分析 (优先)
    if language == "Python":
        try:
            tree = ast.parse(code_text)
            pre_scanner = PreAnalysisVisitor()
            pre_scanner.visit(tree)
            visitor = PythonTaintVisitor(lines, 
                                       custom_sinks=pre_scanner.custom_sinks,
                                       custom_sources=pre_scanner.custom_sources)
            visitor.visit(tree)
            issues.extend(visitor.issues)
        except Exception:
            # Python 2 兼容性或语法错误，跳过 AST，依赖 Regex
            pass

    # 2. Regex 兜底分析 (全语言通用)
    # 对于 Python，即使 AST 成功了，我们也跑一遍 Regex 以查漏补缺
    clean_code = remove_comments(code_text, language)
    clean_lines = clean_code.split('\n')
    regex_rules = RULES_DB.get(language, [])
    
    if regex_rules:
        compiled = [(re.compile(r["pattern"], re.IGNORECASE), r) for r in regex_rules]
        for i, line in enumerate(clean_lines):
            line_no = i + 1
            if not line.strip(): continue
            if any(iss.line_no == line_no and iss.level in ["Critical", "Error"] for iss in issues): 
                continue
                
            for pat, rule in compiled:
                if pat.search(line):
                    issues.append(CodeIssue(line_no, lines[i], rule["id"], rule["level"], rule["message"], rule["category"]))
    
    issues.sort(key=lambda x: x.line_no)
    return issues