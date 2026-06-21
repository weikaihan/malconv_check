import torch

print("正在解析多尺度二分类模型权重结构...")
# 注意：把文件名换成了你新上传的 pth
state = torch.load('malconv_binary_best.pth', map_location='cpu')

for key, value in state.items():
    print(f"{key}: {value.shape}")