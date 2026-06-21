import torch

print("正在解析模型权重结构...")
state = torch.load('malconv1_best.pt', map_location='cpu')

for key, value in state.items():
    print(f"{key}: {value.shape}")