# feature_extractor.py
import pefile
import re
import math

def calculate_entropy(data):
    """计算一段数据的熵值，大于 7.0 通常意味着被加密或加壳"""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_pe_evidence(file_path):
    """提取 PE 文件的三大铁证：高危导入函数、异常节区、可疑字符串"""
    evidence = {
        "suspicious_apis": [],
        "high_entropy_sections": [],
        "suspicious_strings": []
    }
    
    try:
        pe = pefile.PE(file_path)
        
        # 1. 提取导入表 (IAT) 中的敏感 API
        # 重点关注内存注入、键盘监听、注册表修改等危险操作
        high_risk_apis = [
            b"VirtualAlloc", b"WriteProcessMemory", b"CreateRemoteThread", 
            b"SetWindowsHookEx", b"RegSetValueEx", b"HttpSendRequest", 
            b"InternetOpenUrl", b"CryptAcquireContext", b"IsDebuggerPresent"
        ]
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and any(risk in imp.name for risk in high_risk_apis):
                        evidence["suspicious_apis"].append(imp.name.decode('utf-8', 'ignore'))
                        
        # 2. 检查异常的高熵值节区 (判断是否加壳/隐藏病毒体)
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
            entropy = calculate_entropy(section.get_data())
            if entropy > 7.2: # 熵值大于 7.2 非常可疑
                evidence["high_entropy_sections"].append(f"{section_name} (熵值:{entropy:.2f})")
                
        # 3. 提取文件中的明文 URL 或 IP 地址 (C2 通信铁证)
        with open(file_path, "rb") as f:
            content = f.read()
            # 用正则抓取 http/https 网址和 IP 地址
            urls = re.findall(b"https?://[a-zA-Z0-9./_-]+", content)
            ips = re.findall(b"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", content)
            
            # 去重并保存前 5 个最可疑的
            evidence["suspicious_strings"].extend(list(set([u.decode() for u in urls]))[:5])
            evidence["suspicious_strings"].extend(list(set([i.decode() for i in ips]))[:5])

    except Exception as e:
        evidence["error"] = f"解析 PE 结构失败: {str(e)}（可能不是标准的 Windows EXE 文件）"

    return evidence