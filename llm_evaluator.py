import google.generativeai as genai
import os

# 1. 配置你的 API Key
# 建议在实际项目中通过环境变量读取: os.environ.get("GEMINI_API_KEY")
API_KEY = "api_key"  # 请替换为你真实的 API Key
genai.configure(api_key=API_KEY)

def generate_security_report(file_name, malicious_score, is_malware, threshold=0.5):
    """
    调用大语言模型，根据传统模型的打分生成自然语言评估报告
    """
    # 实例化模型 (使用适合复杂推理和文本生成的 pro 模型)
    model = genai.GenerativeModel('gemini-1.5-pro')

    # 精心设计的 Prompt 模板
    prompt = f"""
    你是一个资深的网络安全威胁情报分析师。
    系统刚刚使用基于原始字节的深度学习模型 (MalConv) 对一个未知文件进行了静态扫描。
    请根据以下扫描结果，生成一段专业、客观、简明扼要的分析报告。

    【扫描数据】
    - 文件名称: {file_name}
    - 恶意检出概率得分: {malicious_score} (得分范围 0.0 到 1.0，判定阈值为 {threshold})
    - 系统初步判定: {"恶意文件 ❌" if is_malware else "安全文件 ✅"}

    【报告撰写要求】
    1. 核心结论：用一句话明确指出该文件的当前安全风险级别（如：极低、可疑、极高）。
    2. 数据解读：用通俗的语言向非技术人员解释这个“得分”代表什么。如果得分像 1.7e-09 这样极低，请解释这意味着模型在字节层面完全没有发现已知的恶意特征。
    3. 处置建议：给出下一步的标准安全运营操作（例如：可信放行、建议转入动态沙箱进一步观察、或立即隔离）。
    4. 格式与字数：使用 Markdown 格式，条理清晰，总字数严格控制在 200 字以内。
    """

    try:
        print("正在请求大模型生成评估报告，请稍候...")
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"报告生成失败，API 调用出错: {str(e)}"

# === 本地调试入口 ===
if __name__ == "__main__":
    # 填入我们刚才用白样本跑出来的真实数据
    test_file_name = "00eea85752664955047caad7d6280bc7bf1ab91c61eb9a2542c26b747a12e963.exe"
    test_score = 1.770681712365274e-09
    test_is_malware = False

    print("="*50)
    print("输入的源数据:")
    print(f"文件名: {test_file_name}")
    print(f"得分: {test_score}")
    print(f"判定: {test_is_malware}")
    print("="*50)

    # 生成并打印报告
    report = generate_security_report(
        file_name=test_file_name,
        malicious_score=test_score,
        is_malware=test_is_malware
    )
    
    print("\n【LLM 智能生成的分析报告】")
    print(report)