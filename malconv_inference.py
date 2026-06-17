import numpy as np
import tensorflow as tf
import os

# 1. 核心配置（请务必确保与你训练时的参数完全一致！）
# MalConv 通常固定一个最大输入长度，常见的有 1MB (1048576) 或 2MB (2000000)
MAX_LEN = 1048576  # 注意：请修改为你训练模型时使用的真实长度

# 2. 全局加载模型 (利用全局变量实现常驻内存，避免每次请求引发严重的冷启动延迟)
print("正在加载 MalConv 模型并初始化计算图...")
malconv_model = tf.keras.models.load_model('malconv.h5',compile=False)
print("模型加载完成！")

def preprocess_file(file_path, max_len=MAX_LEN):
    """
    读取文件的原始字节，并将其转化为模型期望的固定长度数组
    """
    # 读取二进制原始数据
    with open(file_path, 'rb') as f:
        bytez = f.read()

    # 将字节转化为 0-255 的整数数组
    b = np.frombuffer(bytez, dtype=np.uint8)

    # 截断或填充操作
    if len(b) > max_len:
        # 如果文件过大，截断尾部多余的字节
        b = b[:max_len]
    else:
        # 如果文件较小，在尾部填充 0 (Padding)
        b = np.pad(b, (0, max_len - len(b)), 'constant', constant_values=0)

    # 增加一个 Batch 维度。Keras 预测时期望的输入 shape 是 (batch_size, sequence_length)
    # 增加维度后，最终返回的 shape 变为 (1, max_len)
    return np.expand_dims(b, axis=0)

def predict_is_malware(file_path, threshold=0.5):
    """
    接收文件路径，输出恶性评估分值和结论
    """
    # 1. 执行预处理
    processed_data = preprocess_file(file_path)

    # 2. 模型预测 (假设你的模型输出层是一个 sigmoid 激活的单神经元，输出 0~1 的概率)
    prediction_score = malconv_model.predict(processed_data, verbose=0)[0][0]

    # 3. 结果判定
    is_malicious = prediction_score >= threshold

    return {
        "file_name": os.path.basename(file_path),
        "malicious_score": float(prediction_score), # 提取为基础的浮点数，方便后续存入数据库
        "is_malware": bool(is_malicious)
    }

# === 本地调试入口 ===
if __name__ == "__main__":
    # 随便找一个本地的 exe 文件测试一下，比如系统自带的记事本
    test_file = r"D:\code\eyi_oranizition\files\begnin\00eea85752664955047caad7d6280bc7bf1ab91c61eb9a2542c26b747a12e963.exe" 
    
    if os.path.exists(test_file):
        print(f"正在分析文件: {test_file}")
        result = predict_is_malware(test_file)
        print(f"分析结果: {result}")
    else:
        print("请提供一个真实的测试文件路径。")