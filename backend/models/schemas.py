from typing import Literal, Optional
from pydantic import BaseModel


class UploadResponse(BaseModel):
    jobId: str
    filename: str
    sizeBytes: int
    flowCount: int


class SuricataMatch(BaseModel):
    sid: int
    rule: str
    severity: Literal["critical", "high", "medium"]
    srcIp: str
    dstIp: str
    proto: str


class SuricataResult(BaseModel):
    matched: bool
    scannedFlows: int
    matchedFlows: int
    rulesEvaluated: int
    durationMs: int
    matches: list[SuricataMatch] = []


class WindowCount(BaseModel):
    label: str
    count: int


class PreprocessingResult(BaseModel):
    status: Literal["complete"]
    remainingFlows: int
    windows: list[WindowCount]
    csvPath: str
    durationMs: int


class Model1Result(BaseModel):
    status: Literal["complete"]
    verdict: Literal["attack", "benign"]
    confidence: float
    benignFlows: int
    attackFlows: int
    durationMs: int


class ClassProbability(BaseModel):
    label: str
    value: float


class Model2Result(BaseModel):
    status: Literal["complete"]
    attackType: str
    confidence: float
    classProbabilities: list[ClassProbability]
    durationMs: int


class FeatureAttribution(BaseModel):
    name: str
    importance: float
    value: str


class XaiResult(BaseModel):
    status: Literal["complete"]
    method: Literal["SHAP", "LIME"]
    features: list[FeatureAttribution]
    durationMs: int


class LlmNarrative(BaseModel):
    status: Literal["complete"]
    model: str
    summary: str
    recommendedAction: str
    durationMs: int


class CandidateRule(BaseModel):
    sid: int
    raw: str
    basedOnFeatures: list[str]
    falsePositiveTestStatus: Literal["pending", "passed", "failed"]
    approvalStatus: Literal["awaiting_review", "approved", "rejected"]


class RuleApprovalRequest(BaseModel):
    sid: int


class PipelineStageUpdate(BaseModel):
    """Shape pushed over the /ws/{jobId} WebSocket after each stage transition."""

    stage: Literal[
        "upload", "suricata", "preprocess", "model1", "model2", "xai", "llm", "rulegen", "dashboard"
    ]
    status: Literal["running", "pass", "alert", "intel", "skipped"]
    payload: Optional[dict] = None
