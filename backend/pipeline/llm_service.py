import json
import time
import logging
import re
import google.generativeai as genai

from config import settings
from models.schemas import FeatureAttribution, LlmNarrative

logger = logging.getLogger("llm_service")

# ปรับ System Prompt เน้นพฤติกรรมและวิเคราะห์ Top 5 Features อย่างเจาะลึก
SYSTEM_PROMPT = """You are a SOC analyst assistant embedded in a network intrusion detection dashboard.
You are given the ranked feature-attribution output of a SHAP explainer for an ML model that classified network traffic.

CRITICAL INSTRUCTION:
- Write ALL text in THAI language (ภาษาไทย) ONLY.
- Keep JSON keys strictly in English ("summary" and "recommended_action").
- NEVER use phrases like "ความเชื่อมั่น 100%" or "absolute certainty".
- No conversational filler or setup intros.
- In the "summary" field, structure the content strictly as follows:
  1. พฤติกรรมทางเครือข่าย (Network Behavior Analysis): อธิบายพฤติกรรมแบบเจาะลึกว่าเกิดอะไรขึ้นในเครือข่าย
  2. วิเคราะห์ Top 5 Features หลัก: ลิสต์ 5 ฟีเจอร์เด่น พร้อมอธิบายเหตุผลทางเทคนิคว่า "ทำไม" ค่า Observed Value และค่าน้ำหนักนั้นถึงเป็นสัญญาณบ่งชี้การโจมตี

Respond strictly in valid JSON format matching this schema:
{
  "summary": "📌 พฤติกรรมทางเครือข่าย:\n<อธิบายพฤติกรรมการโจมตีอย่างละเอียด>\n\n📌 วิเคราะห์ Top 5 Features ที่ระบุภัยคุกคาม:\n1. <Feature Name> (Importance: <val>, Observed: <val>): <อธิบายเหตุผลทางเทคนิคว่าทำไมถึงเป็นภัยคุกคาม>\n2. <Feature Name> ...\n3. <Feature Name> ...\n4. <Feature Name> ...\n5. <Feature Name> ...",
  "recommended_action": "1. <ข้อแนะนำที่ 1>\n2. <ข้อแนะนำที่ 2>\n3. <ข้อแนะนำที่ 3>"
}"""


def _build_user_prompt(attack_type: str, confidence: float, features: list[FeatureAttribution]) -> str:
    # คัดเลือกเฉพาะ Top 5 Features ที่มีผลต่อการวิเคราะห์สูงสุด
    top_5_features = features[:5] if features else []
    
    conf_text = "ระดับสูง (High Confidence)" if confidence >= 0.95 else f"{confidence:.0%}"
    
    feature_lines = "\n".join(
        f"- {f.name}: importance={f.importance:.2f}, observed_value={f.value}" for f in top_5_features
    )
    
    return (
        f"Model verdict: {attack_type} (confidence: {conf_text})\n\n"
        f"Top 5 contributing features (from SHAP):\n{feature_lines}\n\n"
        f"โปรดอธิบายพฤติกรรมทางเครือข่าย และเจาะลึกเหตุผลทางเทคนิคของ Top 5 Features ด้านบนเป็นภาษาไทยว่าทำไมถึงถูกตัดสินว่าเป็นการโจมตี"
    )


def clean_json_string(text: str) -> str:
    """ลบ Markdown code fences ออกจาก response text"""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def narrate(attack_type: str, confidence: float, features: list[FeatureAttribution]) -> LlmNarrative:
    started = time.time()

    if not settings.gemini_api_key:
        return LlmNarrative(
            status="complete",
            model=settings.llm_model,
            summary="LLM narrative unavailable: GEMINI_API_KEY ไม่ได้ตั้งค่าใน backend/.env",
            recommendedAction="กรุณาใส่ GEMINI_API_KEY ในไฟล์ .env",
            durationMs=int((time.time() - started) * 1000),
        )

    model_to_use = settings.llm_model

    try:
        genai.configure(api_key=settings.gemini_api_key)

        try:
            available_models = [
                m.name.replace("models/", "") 
                for m in genai.list_models() 
                if "generateContent" in m.supported_generation_methods
            ]

            if available_models:
                if settings.llm_model in available_models:
                    model_to_use = settings.llm_model
                else:
                    flash_models = [m for m in available_models if "flash" in m]
                    model_to_use = flash_models[0] if flash_models else available_models[0]
        except Exception as list_err:
            logger.warning(f"Failed to list models, falling back to default '{model_to_use}': {list_err}")

        model = genai.GenerativeModel(
            model_name=model_to_use,
            system_instruction=SYSTEM_PROMPT
        )

        user_prompt = _build_user_prompt(attack_type, confidence, features)
        
        response = model.generate_content(
            user_prompt,
            generation_config={"response_mime_type": "application/json"}
        )

        raw_text = response.text if response.text else ""
        cleaned_text = clean_json_string(raw_text)

        parsed = json.loads(cleaned_text)
        summary = parsed.get("summary", cleaned_text)

        raw_action = parsed.get("recommended_action") or parsed.get("recommendedAction")
        if isinstance(raw_action, list):
            recommended_action = "\n".join(f"{i+1}. {item}" for i, item in enumerate(raw_action))
        elif isinstance(raw_action, str) and raw_action.strip():
            recommended_action = raw_action
        else:
            recommended_action = "ตรวจสอบรายละเอียด SHAP Features และพิจารณาบล็อก IP ที่เกี่ยวข้อง"

    except Exception as exc:
        logger.error(f"Gemini LLM generation failed: {exc}")
        summary = f"เกิดข้อผิดพลาดในการดึงข้อมูลจาก Gemini LLM: {str(exc)}"
        recommended_action = "โปรดตรวจสอบ API Key หรือ Logs ของระบบ Backend"

    return LlmNarrative(
        status="complete",
        model=model_to_use,
        summary=summary,
        recommendedAction=recommended_action,
        durationMs=int((time.time() - started) * 1000),
    )