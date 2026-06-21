# malconv_inference.py
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import os

# =====================================================================
# 1. 精准逆向还原：Multi-Scale Bigram ResGate 架构
# =====================================================================
class SEBlock(nn.Module):
    """Squeeze-and-Excitation 通道注意力机制"""
    def __init__(self, in_ch, reduced_ch):
        super(SEBlock, self).__init__()
        self.fc = nn.Sequential(
            # 加入 bias=False 与权重文件对齐
            nn.Linear(in_ch, reduced_ch, bias=False),
            nn.ReLU(),
            nn.Linear(reduced_ch, in_ch, bias=False),
            nn.Sigmoid()
        )

    def forward(self, x):
        y = x.mean(dim=-1) 
        y = self.fc(y).unsqueeze(-1)
        return x * y

class MultiScaleConv(nn.Module):
    """多尺度特征提取器"""
    def __init__(self):
        super(MultiScaleConv, self).__init__()
        # 加入 bias=False
        self.conv_s = nn.Conv1d(16, 85, kernel_size=32, stride=32, padding=0, bias=False)
        self.conv_m = nn.Conv1d(16, 85, kernel_size=64, stride=32, padding=16, bias=False)
        self.conv_l = nn.Conv1d(16, 86, kernel_size=128, stride=32, padding=48, bias=False)
        self.bn = nn.BatchNorm1d(256)
        self.se = SEBlock(256, 64)

    def forward(self, x):
        s = self.conv_s(x)
        m = self.conv_m(x)
        l = self.conv_l(x)
        min_len = min(s.size(2), m.size(2), l.size(2))
        out = torch.cat([s[:, :, :min_len], m[:, :, :min_len], l[:, :, :min_len]], dim=1)
        out = F.relu(self.bn(out))
        out = self.se(out)
        return out

class ResGateBlock(nn.Module):
    """残差门控网络模块"""
    def __init__(self, in_ch, out_ch, kernel, reduced_ch, downsample=False):
        super(ResGateBlock, self).__init__()
        padding = kernel // 2
        stride = 2 if downsample else 1
        
        # 加入 bias=False
        self.conv = nn.Conv1d(in_ch, out_ch, kernel, stride=stride, padding=padding, bias=False)
        self.gate = nn.Conv1d(in_ch, out_ch, kernel, stride=stride, padding=padding, bias=False)
        self.bn = nn.BatchNorm1d(out_ch)
        self.se = SEBlock(out_ch, reduced_ch)
        
        self.has_downsample = downsample
        if downsample:
            self.downsample = nn.Sequential(
                # 加入 bias=False
                nn.Conv1d(in_ch, out_ch, kernel_size=1, stride=stride, bias=False),
                nn.BatchNorm1d(out_ch)
            )

    def forward(self, x):
        c = self.conv(x)
        g = self.gate(x)
        
        min_len = min(c.size(2), g.size(2))
        c, g = c[:, :, :min_len], g[:, :, :min_len]
        
        out = c * torch.sigmoid(g)
        out = self.bn(out)
        out = self.se(out)
        
        res = self.downsample(x) if self.has_downsample else x
        res_len = min(out.size(2), res.size(2))
        
        return F.relu(out[:, :, :res_len] + res[:, :, :res_len])

class MalConvBinary(nn.Module):
    def __init__(self):
        super(MalConvBinary, self).__init__()
        self.embedding = nn.Embedding(257, 16, padding_idx=256)
        self.bigram_embed = nn.Embedding(66049, 16) 
        
        self.bigram_proj = nn.Linear(32, 16)
        self.bigram_bn = nn.BatchNorm1d(16)
        
        self.multi_scale = MultiScaleConv()
        self.res1 = ResGateBlock(256, 256, kernel=16, reduced_ch=64, downsample=True)
        self.res2 = ResGateBlock(256, 128, kernel=8, reduced_ch=32, downsample=True)
        self.res3 = ResGateBlock(128, 128, kernel=4, reduced_ch=32, downsample=False)
        
        self.stage1_fc = nn.Linear(256, 128)
        self.stage1_ln = nn.LayerNorm(128)
        self.stage1_out = nn.Linear(128, 2)
        
        self.stage2_fc = nn.Linear(256, 128)
        self.stage2_ln = nn.LayerNorm(128)
        self.stage2_out = nn.Linear(128, 8)

    def forward(self, x):
        uni = self.embedding(x)
        x_pad = F.pad(x, (0, 1), value=256)
        x_bi = x_pad[:, :-1] * 257 + x_pad[:, 1:]
        bi = self.bigram_embed(x_bi)
        
        feat = torch.cat([uni, bi], dim=-1)   
        feat = self.bigram_proj(feat)         
        feat = feat.transpose(1, 2)           
        feat = self.bigram_bn(feat)
        
        feat = self.multi_scale(feat)
        r1 = self.res1(feat)
        r2 = self.res2(r1)
        r3 = self.res3(r2)
        
        p1 = r1.max(dim=-1)[0]
        s1 = F.relu(self.stage1_ln(self.stage1_fc(p1)))
        out1 = self.stage1_out(s1)  
        
        return out1

# =====================================================================
# 2. 实例化并加载多尺度双核模型
# =====================================================================
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

malconv_model = MalConvBinary().to(device)

weight_path = 'malconv_binary_best.pth'
if os.path.exists(weight_path):
    print(f"[*] 正在加载强力多尺度二分类权重: {weight_path}")
    state_dict = torch.load(weight_path, map_location=device)
    malconv_model.load_state_dict(state_dict) 
    malconv_model.eval()
    print("[*] 恭喜！高级多尺度模型成功启动！🚀")
else:
    print(f"[!] 警告: 未找到权重文件 {weight_path}")

# =====================================================================
# 3. 标准化推理接口
# =====================================================================
def predict_is_malware(file_path, threshold=0.5):
    with open(file_path, 'rb') as f:
        bytez = f.read()
    
    maxlen = 1048576 
    buf = np.ones((maxlen,), dtype=np.int64) * 256
    chunk = np.frombuffer(bytez[:maxlen], dtype=np.uint8)
    buf[:len(chunk)] = chunk
    
    x = torch.from_numpy(buf).long().unsqueeze(0).to(device)
    
    with torch.no_grad():
        logits = malconv_model(x)  
        probs = torch.softmax(logits, dim=1)
        score = probs[0, 1].item()
        
    return {
        "file_name": os.path.basename(file_path),
        "malicious_score": score,
        "is_malware": score >= threshold
    }