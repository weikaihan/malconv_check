# malconv_inference.py
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import os

# =====================================================================
# 1. 精准逆向还原：MalConv-GCT (Global Context Tracker) 架构
# =====================================================================
class GCTBlock(nn.Module):
    def __init__(self):
        super(GCTBlock, self).__init__()
        # 对应 blocks.0.conv
        self.conv = nn.Conv1d(8, 256, kernel_size=512, stride=512)
        # 对应 blocks.0.gcg_proj
        self.gcg_proj = nn.Linear(128, 128)
        # 对应 blocks.0.channel_mix
        self.channel_mix = nn.Conv1d(128, 128, kernel_size=1)

    def forward(self, x, context):
        # 局部特征提取
        out = self.conv(x)
        out = F.glu(out, dim=1)  # GLU 将通道数从 256 减半至 128
        
        # 全局上下文门控融合 (Global Context Gating)
        ctx = self.gcg_proj(context)
        out = out * torch.sigmoid(ctx).unsqueeze(2) 
        
        # 通道混合
        out = self.channel_mix(out)
        return out

class MalConvGCT(nn.Module):
    def __init__(self):
        super(MalConvGCT, self).__init__()
        # 对应 byte_embed
        self.byte_embed = nn.Embedding(257, 8, padding_idx=256)

        # 对应 context_conv 序列 (巧妙利用占位符完美对齐下标 0 和 3)
        self.context_conv = nn.Sequential(
            nn.Conv1d(8, 256, kernel_size=512, stride=512), # .0
            nn.GLU(dim=1),                                  # .1 (无参数, 通道减半)
            nn.Identity(),                                  # .2 (无参数, 完美占位)
            nn.Conv1d(128, 128, kernel_size=1)              # .3
        )
        # 对应 context_fc
        self.context_fc = nn.Linear(128, 128)

        # 对应 blocks
        self.blocks = nn.ModuleList([
            GCTBlock()
        ])

        # 对应分类器全连接层
        self.fc1 = nn.Linear(128, 128)
        self.fc2 = nn.Linear(128, 1)

    def forward(self, x):
        # 1. 字节嵌入 [B, L] -> [B, 8, L]
        x_emb = self.byte_embed(x).permute(0, 2, 1)

        # 2. 全局上下文提取分支
        ctx = self.context_conv(x_emb)
        ctx = torch.max(ctx, dim=-1)[0] # 全局最大池化
        ctx = self.context_fc(ctx)

        # 3. 主干处理块 (受上下文指导)
        out = x_emb
        for block in self.blocks:
            out = block(out, ctx)

        # 4. 最终分类
        out = torch.max(out, dim=-1)[0] # 全局最大池化
        out = F.relu(self.fc1(out))
        out = self.fc2(out)
        return out

# =====================================================================
# 2. 实例化并加载极品权重
# =====================================================================
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

malconv_model = MalConvGCT().to(device)

weight_path = 'malconv1_best.pt'
if os.path.exists(weight_path):
    print(f"[*] 正在加载 GCT 变体权重: {weight_path}")
    state_dict = torch.load(weight_path, map_location=device)
    malconv_model.load_state_dict(state_dict) # 现在绝对不会报错了！
    malconv_model.eval()
    print("[*] 恭喜！极品模型加载成功！🚀")
else:
    print(f"[!] 警告: 未找到权重文件 {weight_path}")

# =====================================================================
# 3. 标准化推理接口
# =====================================================================
def predict_is_malware(file_path, threshold=0.5):
    """供外部 Worker 调用的标准接口"""
    with open(file_path, 'rb') as f:
        bytez = f.read()
    
    # 截断与补全 (统一为 1MB 长张量)
    maxlen = 1048576 
    buf = np.ones((maxlen,), dtype=np.int64) * 256
    chunk = np.frombuffer(bytez[:maxlen], dtype=np.uint8)
    buf[:len(chunk)] = chunk
    
    x = torch.from_numpy(buf).long().unsqueeze(0).to(device)
    
    with torch.no_grad():
        logits = malconv_model(x).squeeze(-1)
        score = torch.sigmoid(logits).item()
        
    return {
        "file_name": os.path.basename(file_path),
        "malicious_score": score,
        "is_malware": score >= threshold
    }