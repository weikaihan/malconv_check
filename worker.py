# worker.py
import asyncio
# 引入数据库模型，注意增加了 AnalysisReport
from models import Sample, DetectionResult, AnalysisReport 

# 导入我们刚刚写好的两个核心工作函数
from malconv_inference import predict_is_malware
from llm_evaluator import generate_security_report

# 假设你之前在 malconv_inference 里已经做了模型缓存，这里直接调用即可
# 或者你可以保留原来 worker.py 里的 get_malconv_model() 逻辑

async def background_analysis_task(sample_id: str, file_path: str, db_session):
    """
    异步并发核心逻辑：流水线式执行 [特征判定] -> [LLM 总结]
    """
    try:
        # 1. 更新数据库状态为 "analyzing"
        sample = db_session.query(Sample).filter(Sample.id == sample_id).first()
        sample.status = "analyzing"
        db_session.commit()
        print(f"⏳ 开始处理样本: {sample_id}")

        # ==========================================
        # 阶段一：传统模型判定层 (获取分数)
        # ==========================================
        print(f"[{sample_id}] 正在执行 MalConv 原始字节深度学习检测...")
        # 真实调用！传入文件路径，拿到包含分数的字典
        result_dict = predict_is_malware(file_path) 
        
        # 将传统模型的分数记录进数据库
        detection_result = DetectionResult(
            sample_id=sample.id,
            model_name="MalConv",
            malicious_score=result_dict['malicious_score']
        )
        db_session.add(detection_result)
        
        # ==========================================
        # 阶段二：LLM 智能增强层 (生成报告)
        # ==========================================
        print(f"[{sample_id}] 正在请求 Gemini 大模型生成评估报告...")
        # 将刚才算出的分数和判定结论，喂给大模型
        llm_summary_text = generate_security_report(
            file_name=result_dict['file_name'],
            malicious_score=result_dict['malicious_score'],
            is_malware=result_dict['is_malware']
        )
        
        # 将大模型生成的自然语言报告记录进数据库
        report = AnalysisReport(
            sample_id=sample.id,
            llm_summary=llm_summary_text
        )
        db_session.add(report)

        # ==========================================
        # 阶段三：收尾与状态确认
        # ==========================================
        sample.status = "completed"
        db_session.commit()
        print(f"✅ 样本 {sample_id} 全流程分析与评估完毕！")

    except Exception as e:
        # 如果中间任何一步（比如文件损坏、API超时）崩了，标记为失败
        sample.status = "failed"
        db_session.commit()
        print(f"❌ 样本 {sample_id} 分析失败: {str(e)}")