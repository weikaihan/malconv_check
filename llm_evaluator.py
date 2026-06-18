# llm_evaluator.py
import os

# 注释掉真实的 API 库导入，彻底禁用联网
# from openai import OpenAI
# API_KEY = "..."
# client = OpenAI(...)

def generate_security_report(file_name, malicious_score, is_malware, threshold=0.5):
    """
    【本地挡板版】屏蔽了大模型 API 调用。
    利用 if-else 直接生成格式化的 Markdown 报告，供前端测试使用。
    """
    print("已禁用大模型联网，正在生成本地快速评估报告...")
    
    # 简单的本地逻辑判断
    if is_malware:
        risk_level = "**极高危** ❌"
        advice = "系统底层检测到强烈的恶意字节特征。建议：立即隔离该文件，并在安全环境下作进一步排查。"
    else:
        if malicious_score > 0.3:
            risk_level = "**可疑** ⚠️"
            advice = "文件具有一定的异常特征，但不属于已知的高危病毒。建议：转入动态沙箱观察运行行为。"
        else:
            risk_level = "**安全** ✅"
            advice = "未检测到明显的恶意代码特征。建议：可信放行。"

    # 组装返回给前端的 Markdown 字符串
    mock_report = f"""
### 本地快速评估报告 (LLM 已禁用)

**风险级别**：{risk_level}

**数据解读**：
该文件名为 `{file_name}`，当前模型检出得分为 `{malicious_score:.6f}`。
*(注：该分数由本地 MalConv 模型直接输出，当前大模型解释功能处于暂时禁用状态。)*

**处置建议**：
{advice}
"""
    return mock_report


# === 本地调试入口 ===
if __name__ == "__main__":
    print(generate_security_report("test_virus.exe", 0.98, True))
    print("-" * 30)
    print(generate_security_report("test_safe.exe", 0.01, False))