# 智能恶意软件静态分析平台 - 应用框架架构设计

## 1. 框架概述 (Framework Overview)

本框架是一个专为网络安全领域设计的**“深度学习 + 大语言模型”双核驱动**的静态分析系统。系统旨在解决传统恶意软件分析中“黑盒模型缺乏解释性”以及“人工逆向分析成本过高”的痛点。

框架采用**前后端分离、异步任务解耦、文件与数据分离**的现代化微服务/单体架构设计理念，具备高并发响应、秒传缓存、以及极强的横向扩展能力。

---

## 2. 系统整体架构设计 (System Architecture)

整个系统由上至下划分为五大核心层级：

### 2.1 表现层 (Presentation Layer)
* **组件**：纯 HTML5 + 原生 JavaScript + Tailwind CSS + Marked.js。
* **职责**：负责与用户进行交互。接管文件拖拽上传，通过轮询（Polling）机制与后端保持异步通信，并利用 Markdown 解析引擎将后端返回的安全报告进行可视化渲染。

### 2.2 网关与接入层 (API Gateway Layer)
* **组件**：FastAPI (基于 ASGI 的高性能 Python Web 框架)。
* **职责**：作为全系统的唯一入口。负责处理 CORS 跨域请求、路由分发、请求参数校验，并将极度耗时的 AI 运算任务推入后台队列，确保主线程不阻塞，实现非同步非阻塞的高吞吐量。

### 2.3 业务逻辑与任务调度层 (Business & Scheduling Layer)
* **组件**：FastAPI `BackgroundTasks` + 独立 `worker.py`。
* **职责**：系统的“中央处理器”。采用状态机模型（Pending -> Analyzing -> Completed/Failed）管理分析任务的生命周期。串联底层特征抽取逻辑与高层 LLM 认知逻辑。

### 2.4 双核 AI 引擎层 (Dual-Core AI Engine Layer)
系统的核心壁垒，采用“算力解耦”设计：
1. **感知核（底层特征引擎 - MalConv）**：基于 TensorFlow 构建的深度卷积神经网络。直接吞吐二进制文件的原始字节（Raw Bytes），无视加壳与混淆，输出高精度的恶性概率分布特征。
2. **认知核（高层推理引擎 - DeepSeek/Gemini）**：接入兼容 OpenAI 标准的大语言模型 API。将感知核输出的概率数值，结合专家级 Prompt 工程，转化为结构化、具备可解释性的威胁情报报告。

### 2.5 数据持久化层 (Data Persistence Layer)
* **组件**：SQLite (基于 SQLAlchemy ORM) + 本地文件系统 (File System)。
* **职责**：严格遵循“文件与数据分离”原则。二进制文件实体落盘至 `tmp_storage`，数据库仅存储文件的 MD5 指纹、状态机标识以及最终生成的 AI 报告，大幅提升检索性能。

---

## 3. 核心数据流转图 (Core Data Flow)

以下为平台处理单个样本的标准生命周期（可使用 Markdown 支持的 Mermaid 语法渲染为流程图）：

```mermaid
graph TD
    A[前端用户] -->|1. 上传 PE 文件| B(FastAPI 主路由)
    A -->|6. 轮询任务状态| B
    B -->|2. 计算 MD5 查重| C{是否命中缓存?}
    C -->|是: 秒传| D[直接返回历史报告]
    C -->|否: 落盘| E[保存至 /tmp_storage]
    E -->|3. 写入数据库状态 pending| F[(SQLite 数据库)]
    E -->|4. 派发异步任务| G[后台 Worker]
    G -->|4.1 读取字节流| H[MalConv 深度学习模型]
    H -->|4.2 返回 0~1 恶性评分| G
    G -->|4.3 组装 Prompt 请求| I[DeepSeek 大模型 API]
    I -->|4.4 返回自然语言安全报告| G
    G -->|5. 任务标记 completed| F
    F -->|7. 数据聚合| B
    B -->|8. 渲染展示| A

## 4. 后续改进
MalConv 是黑盒，但我们可以通过梯度反向传播（Gradient-based Attribution / Saliency Map）来强行撬开它。简而言之：我们要让 TensorFlow 计算出，“到底是哪几个字节，导致了分数飙升到 0.99？

租一台轻量应用服务器（如阿里云、腾讯云，几十块钱一个月），将代码放上去