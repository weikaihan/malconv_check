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
        return {"status": "success", "message": "命中历史缓存", "sample_id": existing_sample.id}
    
    # 3. 创建暂存目录并落盘
    storage_dir = "./tmp_storage"
    os.makedirs(storage_dir, exist_ok=True)
    file_path = os.path.join(storage_dir, file_hash)
    with open(file_path, "wb") as f:
        f.write(content)
        
    # 4. 创建数据库记录
    new_sample = models.Sample(md5_hash=file_hash, file_size=len(content))
    db.add(new_sample)
    db.commit()
    db.refresh(new_sample)
    
    # 5. 将繁重的模型推演任务抛给异步 Worker
    background_tasks.add_task(background_analysis_task, new_sample.id, file_path, db)
    
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
    
    # 如果分析完成，把分数和 DeepSeek 报告一起查出来返回给前端
    if sample.status == "completed":
        result = db.query(models.DetectionResult).filter(models.DetectionResult.sample_id == sample.id).first()
        report = db.query(models.AnalysisReport).filter(models.AnalysisReport.sample_id == sample.id).first()
        
        if result and report:
            response_data["malicious_score"] = result.malicious_score
            response_data["llm_summary"] = report.llm_summary

    return response_data