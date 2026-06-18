# models.py
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Text, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from database import Base 

def generate_uuid():
    return str(uuid.uuid4())

class Sample(Base):
    __tablename__ = 'samples'
    
    # SQLite 没有原生 UUID，改为 String(36) 存储 UUID 字符串
    id = Column(String(36), primary_key=True, default=generate_uuid)
    md5_hash = Column(String(32), unique=True, index=True, nullable=False)
    file_size = Column(Integer, nullable=False)
    status = Column(String(20), default="pending") 
    created_at = Column(DateTime, default=datetime.utcnow)

    results = relationship("DetectionResult", back_populates="sample")
    report = relationship("AnalysisReport", back_populates="sample", uselist=False)

class DetectionResult(Base):
    __tablename__ = 'detection_results'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    sample_id = Column(String(36), ForeignKey('samples.id'), nullable=False)
    
    # 【核心修复】：加上 default="MalConv"，使得模型在未显式提供名称时默认填充
    model_name = Column(String(50), default="MalConv", nullable=False) 
    
    malicious_score = Column(Float, nullable=False)
    
    sample = relationship("Sample", back_populates="results")

class AnalysisReport(Base):
    __tablename__ = 'analysis_reports'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    sample_id = Column(String(36), ForeignKey('samples.id'), nullable=False)
    llm_summary = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    sample = relationship("Sample", back_populates="report")