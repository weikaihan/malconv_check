# main.py
from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from database import SessionLocal, engine
import models

# 这一行非常关键：启动时自动在本地创建 SQLite 文件和表结构
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Malware Analysis Evaluation API")

# 依赖注入：每次 API 请求都获取一个独立的数据库 Session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 下面是你之前的测试接口
@app.get("/api/v1/test_db")
def test_db_connection(db: Session = Depends(get_db)):
    """测试一下数据库能不能正常写入"""
    new_sample = models.Sample(md5_hash="test_hash_12345", file_size=1024)
    db.add(new_sample)
    db.commit()
    db.refresh(new_sample)
    return {"message": "SQLite 写入成功！", "sample_id": new_sample.id}