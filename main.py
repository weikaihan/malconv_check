# main.py
from fastapi import FastAPI, UploadFile, File, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import hashlib
import os

# 导入本地的数据库配置与模型
from database import SessionLocal, engine
import models
# 导入后台异步任务
from worker import background_analysis_task

# 启动时自动在本地创建 SQLite 表结构
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="智能恶意软件静态分析平台 API")

# 配置 CORS 跨域，允许前端 localhost 访问
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 【核心修复 1】启动事件：清理系统意外关闭导致的僵尸任务
@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    try:
        # 查找所有卡在排队或分析中的历史遗留任务
        stuck_samples = db.query(models.Sample).filter(
            models.Sample.status.in_(["pending", "analyzing"])
        ).all()
        
        # 将它们统一重置为 failed，释放死锁状态，让用户可以重新上传重试
        for sample in stuck_samples:
            sample.status = "failed"
            
        if stuck_samples:
            db.commit()
            print(f"[*] 系统自检完成：已清理 {len(stuck_samples)} 个意外中断的僵尸任务。")
    except Exception as e:
        print(f"系统自检异常: {e}")
    finally:
        db.close()

# 数据库会话依赖注入
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/api/v1/analyze")
async def upload_sample(
    background_tasks: BackgroundTasks, 
    file: UploadFile = File(...), 
    db: Session = Depends(get_db)
):
    """接收文件并触发异步分析的核心接口"""
    # 1. 读取并计算文件 MD5 哈希
    content = await file.read()
    file_hash = hashlib.md5(content).hexdigest()
    
    # 2. 查询缓存：如果数据库中已有该哈希，直接返回实现秒传
    existing_sample = db.query(models.Sample).filter(models.Sample.md5_hash == file_hash).first()
    if existing_sample:
        if existing_sample.status == "completed":
            return {"status": "success", "message": "命中历史缓存", "sample_id": existing_sample.id}
        elif existing_sample.status == "failed":
            # 如果之前由于某种原因失败了，给它一次重新做人的机会，覆盖原有数据重试
            existing_sample.status = "pending"
            db.commit()
            
            # 重新落盘并排队
            base_dir = os.path.abspath(os.path.dirname(__file__))
            storage_dir = os.path.join(base_dir, "tmp_storage")
            
            # 【核心修复 2】防止由于暂存文件夹被删而引发 FileNotFoundError 崩溃
            os.makedirs(storage_dir, exist_ok=True)
            
            file_path = os.path.join(storage_dir, f"{file_hash}.vir")
            with open(file_path, "wb") as f:
                f.write(content)
                
            background_tasks.add_task(background_analysis_task, existing_sample.id, file_path)
            return {"status": "accepted", "message": "发现失败残存，正在重新分析", "sample_id": existing_sample.id}
        else:
            # 正在 analyzing 排队中的直接返回
            return {"status": "success", "message": "正在处理中", "sample_id": existing_sample.id}
            
    # 3. 创建暂存目录并落盘
    base_dir = os.path.abspath(os.path.dirname(__file__))
    storage_dir = os.path.join(base_dir, "tmp_storage")
    os.makedirs(storage_dir, exist_ok=True)
    
    # 强行加上 .vir 后缀，一方面防止手滑双击，另一方面绕过杀软自动扫描锁
    file_path = os.path.join(storage_dir, f"{file_hash}.vir")
    with open(file_path, "wb") as f:
        f.write(content)
        
    # 4. 创建数据库记录
    new_sample = models.Sample(md5_hash=file_hash, file_size=len(content))
    db.add(new_sample)
    db.commit()
    db.refresh(new_sample)
    
    # 5. 将繁重的模型推演任务抛给异步 Worker
    background_tasks.add_task(background_analysis_task, new_sample.id, file_path)
    
    return {
        "status": "accepted", 
        "message": "样本已接收，正在队列中排队分析", 
        "sample_id": new_sample.id
    }

@app.get("/api/v1/status/{sample_id}")
def check_status(sample_id: str, db: Session = Depends(get_db)):
    """供前端轮询查询分析进度的接口"""
    sample = db.query(models.Sample).filter(models.Sample.id == sample_id).first()
    if not sample:
        return {"error": "样本不存在"}
        
    response_data = {
        "sample_id": sample.id,
        "status": sample.status
    }
    
    # 如果分析完成，把分数和 DeepSeek (或本地 Mock) 报告一起查出来返回给前端
    # 如果分析完成，把分数和 DeepSeek 报告一起查出来返回给前端
    if sample.status == "completed":
        result = db.query(models.DetectionResult).filter(models.DetectionResult.sample_id == sample.id).first()
        report = db.query(models.AnalysisReport).filter(models.AnalysisReport.sample_id == sample.id).first()
        
        # 分开判断，确保哪怕报告丢了，分数也能传过去
        if result:
            response_data["malicious_score"] = result.malicious_score
        else:
            response_data["malicious_score"] = 0.0
            
        if report:
            response_data["llm_summary"] = report.llm_summary
        else:
            response_data["llm_summary"] = "⚠️ **报告缺失**：该文件属于系统早期分析的历史缓存，当时未生成大模型报告。请略微修改文件内容（或修改文件名）后重新上传，以触发全新的分析流程。"

    return response_data