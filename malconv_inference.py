# malconv_inference.py
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import os

# 1. 模型定义：完整复制自 malconv1(1).py
class MalConv1(nn.Module):
    def __init__(
        self,
        maxlen: int = 2 ** 20,
        input_dim: int = 257,
        embed_dim: int = 128,
        conv_filters: int = 256,
        conv_kernel: int = 500,
        conv_stride: int = 500,
        d_model: int = 128,
        nhead: int = 4,
        num_layers: int = 4,
        d_ff: int = 512,
        dropout: float = 0.1,
        num_classes: int = 1,
    ):
        super().__init__()
        self.embed = nn.Embedding(input_dim, embed_dim, padding_idx=256)
        self.conv_down = nn.Conv1d(embed_dim, conv_filters, kernel_size=conv_kernel, stride=conv_stride)
        self.bn_down = nn.BatchNorm1d(conv_filters)
        self.conv_res1 = nn.Conv1d(conv_filters, conv_filters, kernel_size=3, padding=1)
        self.bn_res1 = nn.BatchNorm1d(conv_filters)
        self.conv_res2 = nn.Conv1d(conv_filters, conv_filters, kernel_size=3, padding=1)
        self.bn_res2 = nn.BatchNorm1d(conv_filters)
        
        if conv_filters != d_model:
            self.proj = nn.Linear(conv_filters, d_model)
        else:
            self.proj = nn.Identity()
            
        seq_len = (maxlen - conv_kernel) // conv_stride + 1
        self.pos_embed = nn.Parameter(torch.randn(1, seq_len, d_model) * 0.02)
        
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, dim_feedforward=d_ff,
            dropout=dropout, activation="gelu", batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.attn_query = nn.Linear(d_model, 1)
        self.classifier = nn.Sequential(
            nn.Linear(d_model, 128),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(128, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.embed(x)
        x = x.permute(0, 2, 1)
        x = self.conv_down(x)
        x = F.relu(self.bn_down(x))
        identity = x
        x = F.relu(self.bn_res1(self.conv_res1(x)))
        x = self.bn_res2(self.conv_res2(x))
        x = F.relu(x + identity)
        x = x.permute(0, 2, 1)
        x = self.proj(x)
        x = x + self.pos_embed[:, :x.size(1), :]
        x = self.transformer(x)
        attn_scores = self.attn_query(x)
        attn_weights = F.softmax(attn_scores, dim=1)
        x = (x * attn_weights).sum(dim=1)
        return self.classifier(x)

# 2. 实例化模型（使用报错日志中反推出来的确切参数）
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

malconv_model = MalConv1(
    maxlen=2**20,
    input_dim=257,
    embed_dim=64,           # 保持这个维度
    conv_filters=128,       # 保持这个维度
    conv_kernel=500,
    conv_stride=500,
    d_model=96,             # 保持这个维度
    nhead=4,
    num_layers=2,           # <--- 【关键修改】改为 2 层，与 .pt 文件对齐
    d_ff=256,               # 保持这个维度
    dropout=0.2,
    num_classes=1
).to(device)

# 3. 加载权重
weight_path = 'malconv1_best.pt'
if os.path.exists(weight_path):
    print(f"[*] 正在加载权重: {weight_path}")
    state_dict = torch.load(weight_path, map_location=device)
    malconv_model.load_state_dict(state_dict)
    malconv_model.eval()
    print("[*] 模型加载成功！")
else:
    print(f"[!] 警告: 未找到权重文件 {weight_path}")

def predict_is_malware(file_path, threshold=0.5):
    """推理接口"""
    with open(file_path, 'rb') as f:
        bytez = f.read()
    
    maxlen = 2**20
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