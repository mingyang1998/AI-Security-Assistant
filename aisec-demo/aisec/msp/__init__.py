"""MSP (Model Security Posture) —— LLM 模型安全监测与响应。

子能力（Plan V0.4 §4.2.2）：
- 及时发现:  prompt_injection / harmful_output / jailbreak / fingerprint
- 及时响应:  alert + 事件流（soc 接管）
- 及时修复:  Demo 阶段不实现（生产需 SFT/DPO/RLHF）

公开 API：
    from aisec.msp import scan_prompt, scan_output, fingerprint_model
    from aisec.msp import run_full_scan
"""
from __future__ import annotations

from .fingerprint import ModelFingerprint, fingerprint_model
from .jailbreak import JailbreakProbe, run_jailbreak_probe
from .harmful_output import HarmClassifier, classify_output
from .prompt_injection import PromptInjectionDetector, scan_prompt
from .runner import MSPReport, run_full_scan

__all__ = [
    "ModelFingerprint",
    "fingerprint_model",
    "JailbreakProbe",
    "run_jailbreak_probe",
    "HarmClassifier",
    "classify_output",
    "PromptInjectionDetector",
    "scan_prompt",
    "MSPReport",
    "run_full_scan",
]
