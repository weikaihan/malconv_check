from openai import OpenAI
import os

# 1. 填入你的 DeepSeek API Key
API_KEY = "sk-2db52f0814a74f8e8977ab0082793a2a"  

# 2. 初始化 OpenAI 客户端，但把请求地址指向 DeepSeek 的服务器
client = OpenAI(
    api_key=API_KEY, 
    base_url="https://api.deepseek.com" # 关键：重定向到 DeepSeek
)

def generate_security_report(file_name, malicious_score, is_malware, threshold=0.5):
    """
    调用 DeepSeek 大模型，根据传统模型的打分生成自然语言评估报告
    """
    prompt = f"""
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
        print("正在请求 DeepSeek 生成评估报告，请稍候...")
        
        # 调用 deepseek-chat 模型 (即 DeepSeek-V3，速度快，非常适合写报告)
        response = client.chat.completions.create(
            model="deepseek-chat", 
            messages=[
                {"role": "system", "content": "你是一个资深的网络安全威胁情报分析师。系统刚刚使用基于原始字节的深度学习模型 (MalConv) 对一个未知文件进行了静态扫描。请你生成一份专业、客观、简明扼要的分析报告。"},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3 # 调低温度值，让安全报告更加严谨、客观，不胡编乱造
        )
        return response.choices[0].message.content
        
    except Exception as e:
        return f"报告生成失败，API 调用出错: {str(e)}"

# === 本地调试入口 ===
if __name__ == "__main__":
    test_file_name = "00eea85752664955047caad7d6280bc7bf1ab91c61eb9a2542c26b747a12e963.exe"
    test_score = 1.770681712365274e-09
    test_is_malware = False

    print("="*50)
    print("输入的源数据:")
    print(f"文件名: {test_file_name}")
    print(f"得分: {test_score}")
    print(f"判定: {test_is_malware}")
    print("="*50)

    report = generate_security_report(
        file_name=test_file_name,
        malicious_score=test_score,
        is_malware=test_is_malware
    )
    
    print("\n【DeepSeek 智能生成的分析报告】")
    print(report)