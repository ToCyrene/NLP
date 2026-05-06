import os
os.environ['NO_PROXY'] = 'localhost,127.0.0.1'
os.environ['no_proxy'] = 'localhost,127.0.0.1'

import streamlit as st
import pandas as pd
import requests
from analyzer import analyze_code_generic, CodeIssue
from rules import RULES_DB

st.set_page_config(
    page_title="Dual-Engine Code Audit",
    layout="wide",
    page_icon="",
    initial_sidebar_state="expanded"
)

AI_SERVER_URL = "http://localhost:7899/scan"
AI_HEALTH_URL = "http://localhost:7899/docs"

def is_pure_comment(content, lang):
    line = content.strip()
    if not line:
        return True 
    
    if lang == "Python":
        if line.startswith("#"): return True
        if line.startswith('"""') or line.startswith("'''"): return True
        return False
    
    c_family = ["C/C++", "Java", "JavaScript/TypeScript", "Go"]
    if any(cl in lang for cl in ["C", "Java", "Go", "Script"]):
        if line.startswith("//"): return True
        if line.startswith("/*"): return True
        return False
        
    return False

def inject_custom_css():
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        
        .stApp { background-color: #F8F9FA; color: #1F1F1F; font-family: 'Inter', sans-serif; }
        [data-testid="stSidebar"] { background-color: #FFFFFF; border-right: 1px solid #E0E0E0; }
        .main-title {
            background: linear-gradient(90deg, #4285F4, #9B72CB);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 700; font-size: 2.5rem; margin-bottom: 20px;
        }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; display: inline-block; margin-right: 8px; }
        
        .badge-ast { background-color: #E6F4EA; color: #137333; border: 1px solid #CEEAD6; }
        .badge-mined { background-color: #FEF7E0; color: #B06000; border: 1px solid #FEEFC3; }
        .badge-expert { background-color: #E8F0FE; color: #1967D2; border: 1px solid #D2E3FC; }
        .badge-hybrid { background-color: #FCE8E6; color: #C5221F; border: 1px solid #F19E99; }
        .badge-ai { background-color: #E0F7FA; color: #006064; border: 1px solid #4DD0E1; }
        
        .streamlit-expanderHeader { font-family: 'Inter', sans-serif; font-weight: 600; }
    </style>
    """, unsafe_allow_html=True)

inject_custom_css()

with st.sidebar:
    st.title(" 规则库概览")
    st.markdown("---")
    
    total_rules = 0
    for lang, rules in RULES_DB.items():
        count = len(rules)
        total_rules += count
        st.markdown(f"**{lang}**: {count} 条规则")
    
    st.markdown("---")
    st.metric("总规则数", total_rules)
    
    st.markdown("---")
    st.title(" 双模集成引擎")
    use_ai_engine = st.toggle("启用 Ensemble (Qwen3 + Llama3)", value=False)
    ai_status_placeholder = st.empty()

    if use_ai_engine:
        try:
            resp = requests.get(AI_HEALTH_URL, timeout=1)
            if resp.status_code == 200:
                ai_status_placeholder.success(" Models Online")
            else:
                ai_status_placeholder.warning(f" 服务异常 (Code: {resp.status_code})")
        except:
            ai_status_placeholder.error(" 无法连接 AI 服务")
            
    st.info(" 静态分析 + AI 双重验证")

st.markdown('<div class="main-title"> 代码漏洞检测系统 (Hybrid)</div>', unsafe_allow_html=True)

col1, col2 = st.columns([2, 1])

with col1:
    input_method = st.radio("选择输入方式", ["直接粘贴代码", "上传文件"], horizontal=True)

code_content = ""
selected_lang = "Python" 

if input_method == "直接粘贴代码":
    selected_lang = st.selectbox("选择语言", list(RULES_DB.keys()))
    code_content = st.text_area("在此粘贴代码...", height=300)
else:
    uploaded_file = st.file_uploader("上传代码文件", type=['py', 'java', 'c', 'cpp', 'js', 'ts', 'go'])
    if uploaded_file is not None:
        code_content = uploaded_file.read().decode("utf-8")
        ext = uploaded_file.name.split('.')[-1].lower()
        ext_map = {
            'py': 'Python', 'java': 'Java', 
            'c': 'C/C++', 'cpp': 'C/C++', 
            'js': 'JavaScript/TypeScript', 'ts': 'JavaScript/TypeScript',
            'go': 'Go'
        }
        selected_lang = ext_map.get(ext, "Python")
        st.success(f"已加载文件: {uploaded_file.name} (识别为 {selected_lang})")

if st.button("开始全面检测", type="primary"):
    if not code_content.strip():
        st.warning("请输入代码或上传文件。")
    else:
        with st.spinner(f"正在执行深度静态分析 (Taint Propagation + AST) - {selected_lang}..."):
            results = analyze_code_generic(code_content, selected_lang)
        
        ai_lines = set()
        
        if use_ai_engine:
            with st.spinner("正在请求双模型集成推理 (Ensemble Inference)..."):
                try:
                    lines_raw = code_content.split('\n')
                    code_with_lines = "\n".join([f"{i+1} {line}" for i, line in enumerate(lines_raw)])
                    
                    resp = requests.post(
                        AI_SERVER_URL, 
                        json={"code": code_with_lines},
                        timeout=90
                    )
                    
                    if resp.status_code == 200:
                        data = resp.json()
                        ai_lines = set(data.get("vuln_lines", []))
                    else:
                        st.warning(f"AI 服务返回异常状态码: {resp.status_code}")
                except Exception as e:
                    st.error(f"AI 推理过程出错: {str(e)}")

        sa_map = {r.line_no: r for r in results}
        lines_list = code_content.split('\n')
        
        for line_no in ai_lines:
            if line_no in sa_map:
                target_issue = sa_map[line_no]
                target_issue.level = "Critical"
                target_issue.message = f"[ 双模确认] {target_issue.message}"
                target_issue.rule_id = f"HYBRID_{target_issue.rule_id}"
            else:
                if 0 < line_no <= len(lines_list):
                    content_str = lines_list[line_no - 1]
                    new_issue = CodeIssue(
                        line_no=line_no,
                        content=content_str,
                        rule_id="AI_SEMANTIC_DETECT",
                        level="Error",
                        message="AI 语义分析检测到潜在逻辑漏洞",
                        category="AI Detected"
                    )
                    results.append(new_issue)
        
        results.sort(key=lambda x: x.line_no)

        results = [
            r for r in results 
            if not is_pure_comment(r.content, selected_lang)
        ]
        
        st.markdown("###  检测报告")
        
        if not results:
            st.success(" 未发现明显的安全漏洞或风险 (注：已自动忽略注释行)。")
        else:
            crit_count = sum(1 for r in results if r.level == 'Critical')
            high_count = sum(1 for r in results if r.level == 'Error')
            warn_count = len(results) - crit_count - high_count
            
            k1, k2, k3 = st.columns(3)
            k1.metric("Critical", crit_count)
            k2.metric("Error", high_count)
            k3.metric("Warning", warn_count)
            
            st.markdown("---")

            for item in results:
                rule_id_str = str(item.rule_id)
                is_hybrid = rule_id_str.startswith("HYBRID_")
                is_ai_only = rule_id_str == "AI_SEMANTIC_DETECT"
                
                if is_hybrid:
                    badge_html = '<span class="badge badge-hybrid"> Ensemble + SA</span>'
                    border_color = "#C5221F"
                elif is_ai_only:
                    badge_html = '<span class="badge badge-ai"> Dual AI Found</span>'
                    border_color = "#006064"
                elif "AST" in rule_id_str:
                    badge_html = '<span class="badge badge-ast">AST Analysis</span>'
                    border_color = "#EA4335" if item.level == "Critical" else "#FBBC04"
                else:
                    badge_html = '<span class="badge badge-expert">Expert Regex</span>'
                    border_color = "#4285F4"
                
                with st.expander(f"Line {item.line_no}: {item.message}", expanded=True):
                    st.markdown(f"""
                    <div style="margin-bottom: 8px; border-left: 4px solid {border_color}; padding-left: 10px;">
                        {badge_html}
                        <span style="color: #5f6368; font-size: 0.9em;">Category: <b>{item.category}</b></span>
                    </div>
                    """, unsafe_allow_html=True)
                    st.code(item.content, language=selected_lang.lower().split('/')[0])

            if results:
                csv_data = []
                for r in results:
                    r_type = "Regex"
                    if str(r.rule_id).startswith("HYBRID"): r_type = "Hybrid"
                    elif str(r.rule_id) == "AI_SEMANTIC_DETECT": r_type = "AI-Only"
                    
                    csv_data.append({
                        "Line": r.line_no,
                        "Level": r.level,
                        "Type": r_type,
                        "Message": r.message,
                        "Content": r.content
                    })
                df_export = pd.DataFrame(csv_data)
                st.download_button(
                    label=" 导出 CSV 报告",
                    data=df_export.to_csv(index=False).encode('utf-8'),
                    file_name='security_report.csv',
                    mime='text/csv',
                )