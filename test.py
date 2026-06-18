# === 本地调试入口 ===
if __name__ == "__main__":
    # 把你想测试的正常文件路径都放进这个列表里
    test_files = [
        r"D:\code\eyi_oranizition\files\begnin\00eea85752664955047caad7d6280bc7bf1ab91c61eb9a2542c26b747a12e963.exe",
        r"D:\code\eyi_oranizition\files\begnin\0a8deb24eef193e13c691190758c349776eab1cd65fba7b5dae77c7ee9fcc906.exe"
    ]
    
    print(f"开始进行白样本测试，当前判定阈值为: 0.5")
    print("-" * 50)
    
    for file_path in test_files:
        if os.path.exists(file_path):
            try:
                result = predict_is_malware(file_path)
                # 打印结果：文件名 -> 恶意得分 -> 是否恶意
                print(f"文件: {result['file_name']:<15} | 得分: {result['malicious_score']:.4f} | 判定: {'恶意 ❌' if result['is_malware'] else '安全 ✅'}")
            except Exception as e:
                print(f"分析 {file_path} 时发生错误: {e}")
        else:
            print(f"文件不存在，请检查路径: {file_path}")
            
    print("-" * 50)
    print("测试完毕！")