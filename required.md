# 智能恶意软件静态分析平台 - 部署与启动指南

本项目是一个基于 FastAPI + 深度学习 (MalConv) 的高并发异步恶意软件分析系统。为了确保系统在本地或服务器上顺利运行，请严格按照以下步骤进行环境配置与启动。

## 1. 环境依赖 (Dependencies)

系统推荐使用 **Python 3.8 至 Python 3.11** 之间的版本（注意：部分过高版本的 Python 可能与 TensorFlow 的特定版本存在兼容问题）。

### 1.1 一键安装命令
请在项目根目录打开终端（Windows 推荐使用 PowerShell 或 CMD），运行以下命令一次性安装所有核心依赖：

```bash
python -m pip install fastapi uvicorn python-multipart sqlalchemy numpy tensorflow openai

依赖库说明：

fastapi & uvicorn: 提供极其强悍的高性能异步后端和内置的 API 文档引擎。
python-multipart: 必装！ FastAPI 处理前端大文件上传 (UploadFile) 的底层依赖。
sqlalchemy: 处理与 SQLite 的对象关系映射（ORM），管理历史记录与秒传缓存。
numpy & tensorflow: 驱动底层 MalConv 原始字节识别的 AI 算力引擎。
openai: 预留的大语言模型 API SDK（目前在代码中已被 Mock 挡板替换，供未来升级使用）。

#### 2  启动命令
在根目录下启动
python -m uvicorn main:app --host 0.0.0.0 --port 8000
python -m http.server 3000
随即访问localhost：3030