# worker.py
import time
import models
# 1. 关键修复：导入数据库连接池
from database import SessionLocal 
from malconv_inference import predict_is_malware
from llm_evaluator import generate_security_report

# 2. 关键修复：去掉了 async，去掉了 db_session 参数
def background_analysis_task(sample_id: str, file_path: str):
    # 3. 关键修复：Worker 自己创建专属的数据库连接
    db_session = SessionLocal() 
    
    try:
        # 替换斜杠，防止 Windows 路径转义 bug
        safe_file_path = file_path.replace("\\", "/")
        
        # 更新状态为分析中
        sample = db_session.query(models.Sample).filter(models.Sample.id == sample_id).first()
        sample.status = "analyzing"
        db_session.commit()

        print(f"[{sample_id}] 正在执行 MalConv 原始字节深度学习检测...")
        
        # 避开杀软锁定
        time.sleep(0.5)

        # 执行底层推演
        result_dict = predict_is_malware(safe_file_path) 
        
        detection_result = models.DetectionResult(
            sample_id=sample.id,
            malicious_score=result_dict['malicious_score']
        )
        db_session.add(detection_result)
        
        # 执行 LLM 生成
        llm_summary_text = generate_security_report(
            file_name=result_dict['file_name'],
            malicious_score=result_dict['malicious_score'],
            is_malware=result_dict['is_malware']
        )
        report = models.AnalysisReport(
            sample_id=sample.id,
            llm_summary=llm_summary_text
        )
        db_session.add(report)

        # 完成收尾
        sample.status = "completed"
        db_session.commit()
        print(f"[{sample_id}] 分析圆满完成！")
        
    except Exception as e:
        # 【关键修复】如果报错是因为数据库自身引起的，必须先回滚洗清异常状态，否则接下来的 query 会引发二次崩溃！
        db_session.rollback()
        
        # 发生错误时，将状态改写为 failed
        sample = db_session.query(models.Sample).filter(models.Sample.id == sample_id).first()
        if sample:
            sample.status = "failed"
            db_session.commit()
        print(f"❌ 样本 {sample_id} 分析失败: {str(e)}")
        
    finally:
        # 4. 关键修复：无论分析成功还是报错，最后必须关闭数据库连接，防止内存泄漏！
        db_session.close()