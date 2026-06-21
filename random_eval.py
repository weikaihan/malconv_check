import os
import random
import time
# 从我们刚写好的推理核心中导入检测函数
from malconv_inference import predict_is_malware

def random_evaluate_folder(folder_path, true_is_malware, min_samples=10, max_samples=50):
    """
    从指定文件夹中随机抽取样本进行准确率测试
    
    :param folder_path: 存放样本的文件夹路径
    :param true_is_malware: 这个文件夹里的真实属性 (True 表示全都是病毒，False 表示全都是良性)
    :param min_samples: 最小抽取数量
    :param max_samples: 最大抽取数量
    """
    if not os.path.exists(folder_path):
        print(f"[!] 错误: 找不到文件夹路径 {folder_path}")
        return

    # 获取文件夹下的所有文件
    all_files = [
        os.path.join(folder_path, f) 
        for f in os.listdir(folder_path) 
        if os.path.isfile(os.path.join(folder_path, f))
    ]
    
    total_available = len(all_files)
    if total_available == 0:
        print(f"[!] 错误: 文件夹 {folder_path} 中没有任何文件！")
        return

    # 确定要抽取的数量（在 10-50 之间随机，如果文件总数不够则取最大文件数）
    num_to_sample = random.randint(min_samples, max_samples)
    num_to_sample = min(num_to_sample, total_available)

    print(f"[*] 正在从 {total_available} 个文件中随机抽取 {num_to_sample} 个进行测试...")
    
    # 随机无放回抽样
    sampled_files = random.sample(all_files, num_to_sample)
    
    correct_count = 0
    error_list = []  # 记录判断错误的样本，方便后续分析
    
    folder_type_name = "恶意样本(黑)" if true_is_malware else "良性样本(白)"
    print(f"[*] 真实标签认定为: {folder_type_name}")
    print("-" * 60)

    start_time = time.time()

    # 遍历测试
    for i, file_path in enumerate(sampled_files, 1):
        file_name = os.path.basename(file_path)
        try:
            # 调用你的模型进行推理
            result = predict_is_malware(file_path)
            pred_is_malware = result['is_malware']
            score = result['malicious_score']
            
            # 判断是否预测正确
            if pred_is_malware == true_is_malware:
                correct_count += 1
                status = "✅ 正确"
            else:
                status = "❌ 错误"
                error_list.append((file_name, score))

            print(f"[{i:02d}/{num_to_sample}] {status} | 得分: {score:.4f} | 文件: {file_name[:30]}...")
            
        except Exception as e:
            print(f"[{i:02d}/{num_to_sample}] ⚠️ 异常 | 文件: {file_name[:30]}... | 报错: {e}")

    end_time = time.time()
    
    # 打印最终报告
    accuracy = (correct_count / num_to_sample) * 100
    print("\n" + "=" * 60)
    print("📊 测试结果统计报告")
    print("=" * 60)
    print(f"🏷️ 测试集属性: {folder_type_name}")
    print(f"🧪 抽样总数量: {num_to_sample} 个")
    print(f"✅ 判断正确数: {correct_count} 个")
    print(f"❌ 判断错误数: {num_to_sample - correct_count} 个")
    print(f"⏱️ 耗时/速度 : {(end_time - start_time):.2f} 秒 (约 {((end_time - start_time)/num_to_sample):.2f} 秒/个)")
    print(f"🎯 模型准确率: {accuracy:.2f} %")
    
    # 如果有误判的，打印出来方便逆向分析
    if error_list:
        print("-" * 60)
        print("🔍 误判样本明细 (可用于后续分析和 Threshold 微调):")
        for err_name, err_score in error_list:
            print(f"   - {err_name} (得分: {err_score:.4f})")
    print("=" * 60 + "\n")


# === 快速测试入口 ===
if __name__ == "__main__":
    """
    # 测试白样本 (良性文件)
    print(">>> 开始进行 [良性样本] 测试任务 <<<")
    random_evaluate_folder(
        folder_path=r"F:\share\malconv\ember-master\DikeDataset-main\files\benign", 
        true_is_malware=False,   # 白样本文件夹的真实标签为 False
        min_samples=10, 
        max_samples=50
    )
    """
    # 测试黑样本 (恶意文件) 
    print(">>> 开始进行 [恶意样本] 测试任务 <<<")
    random_evaluate_folder(
        folder_path=r"F:\share\恶意代码实验1\自建恶意代码\1", 
        true_is_malware=True,    # 黑样本文件夹的真实标签为 True
        min_samples=10, 
        max_samples=50
    )
    