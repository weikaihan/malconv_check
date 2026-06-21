# llm_evaluator.py
import os
from openai import OpenAI

# 1. 配置你的大模型 API 密钥
API_KEY = "api_key"  # 请替换为真实的 Key
BASE_URL = "https://api.deepseek.com/v1"

client = OpenAI(api_key=API_KEY, base_url=BASE_URL)

def generate_security_report(file_name, malicious_score, is_malware, pe_evidence=None, threshold=0.5):
    if not is_malware:
        return f"### 🟢 安全判定报告\n**样本**：`{file_name}`\n**得分**：`{malicious_score:.4f}`\n判定为良性文件，放行。"

    # 将证据字典转化为文本
    evidence_text = "未提取到 PE 结构证据。"
    if pe_evidence:
        apis = ", ".join(pe_evidence.get('suspicious_apis', [])) or "无"
        sections = ", ".join(pe_evidence.get('high_entropy_sections', [])) or "无"
        strings = ", ".join(pe_evidence.get('suspicious_strings', [])) or "无"
        
        evidence_text = f"""
        - 🔴 检出的高危 API 调用：{apis}
        - 🟠 发现的高熵值/加壳节区：{sections}
        - 🌐 提取到的可疑网络地址：{strings}
        """

    # 【核心修改】：把铁证写进提示词！强制大模型根据证据说话
    prompt = f"""
    你是一名高级威胁情报分析师（CTI）。
    请基于底层的 AI 评分以及真实的逆向解剖证据，编写一份《静态威胁研判报告》。
    
    【基础情报】
    - 样本名称：{file_name}
    - AI 危险打分：{malicious_score:.4f} (阈值 {threshold})
    
    【🔧 真实解剖铁证 (非常重要)】
    {evidence_text}

    请输出 Markdown 报告，包含：
    ### 1. 🛡️ 威胁定性与行为剖析
    (必须严格基于提供的【真实解剖铁证】分析。比如提取到了 VirtualAlloc 就说明有内存注入，提取到了 URL 就说明有外部通信。绝不允许无中生有！如果铁证是“无”，请基于 AI 危险打分给出合理猜测，并标明“缺少明显静态证据，建议动态沙箱分析”。)
    
    ### 2. 🔬 神经网络引擎洞察
    (解释为什么底层 AI 引擎会打出这个分数)
    
    ### 3. ⚔️ 应急响应处置建议
    """

    try:
        response = client.chat.completions.create(
            model="deepseek-chat",  # 确保这里是你要调用的模型名字
            messages=[
                {"role": "system", "content": "你是一名严谨的网络安全技术专家，只输出专业的技术分析与应急响应建议，绝不使用俏皮话或大白话。"},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,  # 降低温度，让模型的推测更加严谨、克制
            timeout=20  
        )
        report_markdown = response.choices[0].message.content
        print("[*] 专业版大模型威胁推演报告生成完毕！")
        return report_markdown
        
    except Exception as e:
        print(f"[!] 大模型 API 调用失败: {e}")
        # API 崩溃时的灾备显示
        return f"### 🔴 高危告警 (AI 研判服务异常)\n\n**样本**：`{file_name}`\n**得分**：`{malicious_score:.4f}`\n\n系统已将其判定为恶意软件。但当前 AI 分析接口异常，错误详情：{e}。\n\n**处置建议**：立即封堵该文件，并转交安全团队人工介入提取 IOC。"

# 本地快速测试代码
if __name__ == "__main__":
    '''print("--- 测试白样本 ---")
    print(generate_security_report("safe_app.exe", 0.1234, False))
    '''
    print("\n--- 测试黑样本 ---")
    print(generate_security_report("1.ole", 0.9876, True))