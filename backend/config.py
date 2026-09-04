import os
from pathlib import Path
from typing import List, Set
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# --------------------------------------------------------------------------
# 1. Pydantic Settings Class (ดึงค่าจาก .env หรือใช้ Default)
# --------------------------------------------------------------------------
class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Base Directory (อ้างอิงตำแหน่งของ config.py)
    base_dir: Path = Path(__file__).resolve().parent

    # LLM Configuration (Gemini & Anthropic)
    gemini_api_key: str = Field(default="", alias="GEMINI_API_KEY")
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")
    anthropic_model: str = Field(default="claude-3-5-sonnet-20241022", alias="ANTHROPIC_MODEL")
    llm_model: str = Field(default="gemini-3.6-flash", alias="LLM_MODEL")  # ปรับแก้ให้อ่านค่า alias LLM_MODEL จาก .env

    # Suricata Settings
    suricata_bin: str = Field(
        default=r"C:\Program Files\Suricata\suricata.exe", 
        alias="SURICATA_BIN"
    )
    suricata_rules_path: str = Field(
        default=r"D:\backend (1)\backend\rules\combined_suricata.rules", 
        alias="SURICATA_RULES_PATH"
    )

    # Detection Thresholds
    anomaly_score_threshold: float = Field(default=60.0, alias="ANOMALY_SCORE_THRESHOLD")
    tier2_ml_confirmation_threshold: float = Field(default=0.85, alias="TIER2_ML_CONFIRMATION_THRESHOLD")

    # API / Server Settings
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    max_upload_mb: int = 200
    allowed_upload_extensions: Set[str] = {".pcap", ".pcapng"}

    # Rule Generator Review Gate
    rulegen_fp_test_max_hits: int = 5
    rulegen_top_k_features: int = 2

    # Dynamic Directories
    @property
    def dataset_dir(self) -> Path:
        return self.base_dir / "Dataset"

    @property
    def cic_csv_dir(self) -> Path:
        return self.dataset_dir / "CICIDS2017_CSV"

    @property
    def models_dir(self) -> Path:
        return self.base_dir / "models"

    @property
    def uploads_dir(self) -> Path:
        return self.base_dir / "uploads"

    @property
    def results_dir(self) -> Path:
        return self.base_dir / "results"

    @property
    def suricata_workdir(self) -> Path:
        return self.results_dir / "_suricata_run"

    # Model Artifact Paths
    @property
    def model_cic_path(self) -> Path:
        return self.models_dir / "model_cic.json"

    @property
    def label_encoder_cic_path(self) -> Path:
        return self.models_dir / "le_cic.pkl"

    @property
    def train_report_path(self) -> Path:
        return self.models_dir / "train_report.txt"

    @property
    def anomaly_model_path(self) -> Path:
        return self.models_dir / "anomaly_iso_forest.pkl"

    @property
    def anomaly_scaler_path(self) -> Path:
        return self.models_dir / "anomaly_scaler.pkl"

    @property
    def anomaly_score_bounds_path(self) -> Path:
        return self.models_dir / "anomaly_score_bounds.json"

    @property
    def feature_schema_cic_path(self) -> Path:
        return self.models_dir / "feature_schema_cic.json"

    def ensure_directories(self) -> None:
        """สร้าง Directory ที่จำเป็นโดยอัตโนมัติ"""
        for folder in (self.dataset_dir, self.cic_csv_dir, self.models_dir, self.uploads_dir, self.results_dir):
            folder.mkdir(parents=True, exist_ok=True)


# Instantiation
settings = Settings()
settings.ensure_directories()


# --------------------------------------------------------------------------
# 2. Module-Level Exports ( Backward Compatibility สำหรับ Pipeline )
# --------------------------------------------------------------------------

# Paths (แปลงเป็น str เพื่อรองรับ os.path และ subprocess ได้ทันที)
SURICATA_BIN: str = str(settings.suricata_bin)
SURICATA_RULES_PATH: str = str(settings.suricata_rules_path)
SURICATA_WORKDIR: str = str(settings.suricata_workdir)

MODEL_CIC_PATH: str = str(settings.model_cic_path)
LABEL_ENCODER_CIC_PATH: str = str(settings.label_encoder_cic_path)
ANOMALY_MODEL_PATH: str = str(settings.anomaly_model_path)
ANOMALY_SCALER_PATH: str = str(settings.anomaly_scaler_path)
ANOMALY_SCORE_BOUNDS_PATH: str = str(settings.anomaly_score_bounds_path)

# Thresholds
ANOMALY_SCORE_THRESHOLD: float = settings.anomaly_score_threshold
TIER2_ML_CONFIRMATION_THRESHOLD: float = settings.tier2_ml_confirmation_threshold

# API Keys & Models
ANTHROPIC_API_KEY: str = settings.anthropic_api_key
ANTHROPIC_MODEL: str = settings.anthropic_model
GEMINI_API_KEY: str = settings.gemini_api_key
LLM_MODEL: str = settings.llm_model


# --------------------------------------------------------------------------
# 3. Strict CICIDS2017 Feature Schema Constants
# --------------------------------------------------------------------------
cic_feature_columns: List[str] = [
    "ip_version",
    "bidirectional_duration_ms",
    "bidirectional_packets",
    "bidirectional_bytes",
    "src2dst_duration_ms",
    "src2dst_packets",
    "src2dst_bytes",
    "dst2src_duration_ms",
    "dst2src_packets",
    "dst2src_bytes",
    "bidirectional_min_ps",
    "bidirectional_mean_ps",
    "bidirectional_stddev_ps",
    "bidirectional_max_ps",
    "src2dst_min_ps",
    "src2dst_mean_ps",
    "src2dst_stddev_ps",
    "src2dst_max_ps",
    "dst2src_min_ps",
    "dst2src_mean_ps",
    "dst2src_stddev_ps",
    "dst2src_max_ps",
    "bidirectional_min_piat_ms",
    "bidirectional_mean_piat_ms",
    "bidirectional_stddev_piat_ms",
    "bidirectional_max_piat_ms",
    "src2dst_min_piat_ms",
    "src2dst_mean_piat_ms",
    "src2dst_stddev_piat_ms",
    "src2dst_max_piat_ms",
    "dst2src_min_piat_ms",
    "dst2src_mean_piat_ms",
    "dst2src_stddev_piat_ms",
    "dst2src_max_piat_ms",
    "bidirectional_syn_packets",
    "bidirectional_cwr_packets",
    "bidirectional_ece_packets",
    "bidirectional_urg_packets",
    "bidirectional_ack_packets",
    "bidirectional_psh_packets",
    "bidirectional_rst_packets",
    "bidirectional_fin_packets",
    "src2dst_syn_packets",
    "src2dst_cwr_packets",
    "src2dst_ece_packets",
    "src2dst_urg_packets",
    "src2dst_ack_packets",
    "src2dst_psh_packets",
    "src2dst_rst_packets",
    "src2dst_fin_packets",
    "dst2src_syn_packets",
    "dst2src_cwr_packets",
    "dst2src_ece_packets",
    "dst2src_urg_packets",
    "dst2src_ack_packets",
    "dst2src_psh_packets",
    "dst2src_rst_packets",
    "dst2src_fin_packets",
    "application_name",
    "application_category_name",
    "application_is_guessed",
    "application_confidence",
    "requested_server_name",
    "client_fingerprint",
    "server_fingerprint",
    "user_agent",
    "content_type"
]

# Validation
assert len(cic_feature_columns) == 67, f"cic_feature_columns must have 67 columns, got {len(cic_feature_columns)}"
assert len(set(cic_feature_columns)) == len(cic_feature_columns), "Duplicate column name in cic_feature_columns"

ctu_feature_columns: List[str] = []
FIVE_TUPLE_COLUMNS: List[str] = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]