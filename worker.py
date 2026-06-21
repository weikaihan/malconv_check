# worker.py
import time
import models
from database import SessionLocal 
from malconv_inference import predict_is_malware
from llm_evaluator import generate_security_report
from feature_extractor import extract_pe_evidence

def background_analysis_task(sample_id: str, file_path: str):
    db_session = SessionLocal() 
    try:
        safe_file_path = file_path.replace("\\", "/")
        
        # 更新状态为分析中
        sample = db_session.query(models.Sample).filter(models.Sample.id == sample_id).first()
        sample.status = "analyzing"
        db_session.commit()

        # 1. 跑深度学习模型打分
        print(f"[{sample_id}] 正在执行 MalConv 原始字节深度学习检测...")
        time.sleep(0.5) # 避开杀软锁定
        result_dict = predict_is_malware(safe_file_path) 
        
        detection_result = models.DetectionResult(
            sample_id=sample.id,
            malicious_score=result_dict['malicious_score']
        )
        db_session.add(detection_result)
        
        # ==========================================
        # 🟢 性能优化：按需解剖 PE 特征
        # ==========================================
        pe_evidence = None
        if result_dict['is_malware']:
            print(f"[{sample_id}] ⚠️ 触发高危告警！正在提取 PE 文件静态特征铁证...")
            pe_evidence = extract_pe_evidence(safe_file_path)
        else:
            print(f"[{sample_id}] ✅ 判定为安全文件，已跳过 PE 解剖与特征提取。")

        # 3. 生成最终报告 
        # (如果 is_malware 为 False，llm_evaluator 内部会直接短路返回，不消耗 API)
        print(f"[{sample_id}] 正在生成分析报告...")
        llm_summary_text = generate_security_report(
            file_name=result_dict['file_name'],
            malicious_score=result_dict['malicious_score'],
            is_malware=result_dict['is_malware'],
            pe_evidence=pe_evidence  # 安全文件传的是 None，恶意文件传的是铁证字典
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
        db_session.rollback()
        sample = db_session.query(models.Sample).filter(models.Sample.id == sample_id).first()
        if sample:
            sample.status = "failed"
            db_session.commit()
        print(f"❌ 样本 {sample_id} 分析失败: {str(e)}")
        
    finally:
        db_session.close()