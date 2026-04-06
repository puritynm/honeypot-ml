"""
Honeypot ML System — Main Orchestrator
Runs the full pipeline: telemetry → features → training → alerting → report.
"""

import sys
import json
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.honeypot.telemetry import HoneypotTelemetry
from src.pipeline.feature_engineering import FeaturePipeline
from src.ml.train import run_training, RuleBasedDetector
from src.alerts.engine import AlertEngine

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║        HONEYPOT ML DETECTION SYSTEM  v1.0                   ║
║        Multi-Layer · Supervised ML · SOC Alert Engine        ║
╚══════════════════════════════════════════════════════════════╝
"""


def print_section(title: str):
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")


def main():
    print(BANNER)
    t0 = time.time()

    # ── Phase 1: Telemetry collection ─────────────────────────────────────
    print_section("Phase 1 · Honeypot Telemetry Generation")
    ht  = HoneypotTelemetry(seed=42)
    raw = ht.generate_full_dataset()
    total_events = sum(len(v) for v in raw.values())
    print(f"  Total events collected: {total_events:,}")

    # ── Phase 2: Feature engineering ──────────────────────────────────────
    print_section("Phase 2 · Feature Engineering")
    pipeline   = FeaturePipeline()
    layer_data = pipeline.fit_transform(raw)

    # ── Phase 3: Model training & evaluation ───────────────────────────────
    print_section("Phase 3 · ML Model Training & Evaluation")
    ml_detector, eval_report = run_training(layer_data)

    # ── Phase 4: Alert engine integration ─────────────────────────────────
    print_section("Phase 4 · Alert Engine (ML-Integrated)")
    alert_engine = AlertEngine(suppression_threshold=0.35)
    rule_detector = RuleBasedDetector()

    for layer, (X, y, _) in layer_data.items():
        ml_scores  = ml_detector.predict_proba(X, layer)
        rule_preds = rule_detector.predict(X, layer)

        # Re-attach original event dicts for context enrichment
        alerts = alert_engine.batch_process(
            events     = raw[layer],
            layer      = layer,
            ml_scores  = ml_scores,
            rule_preds = rule_preds,
        )
        print(f"  [{layer:8s}] {len(alerts):4d} active alerts generated")

    # ── Phase 5: Reporting ─────────────────────────────────────────────────
    print_section("Phase 5 · Summary Report")
    stats    = alert_engine.statistics()
    campaigns = alert_engine.campaign_summary()
    queue    = alert_engine.get_priority_queue()

    print(f"\n  Events processed:    {stats['total_events_processed']:,}")
    print(f"  Alerts raised:       {stats['alerts_raised']:,}")
    print(f"  Alerts suppressed:   {stats['alerts_suppressed']:,}  ({stats['suppression_rate_%']}%)")
    print(f"  Campaigns detected:  {stats['campaigns_detected']}")

    print("\n  Severity distribution:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = stats["severity_distribution"].get(sev, 0)
        bar   = "█" * (count // 5)
        print(f"    {sev:9s} {count:4d}  {bar}")

    print("\n  False-positive reduction vs rule-based:")
    overall_fp_rule = 0
    overall_fp_ml   = 0
    for layer, data in eval_report.items():
        fp_r = data["rule_based"]["false_positives"]
        fp_m = data["ml_model"]["false_positives"]
        overall_fp_rule += fp_r
        overall_fp_ml   += fp_m
        print(f"    {layer:10s}  Rules FP={fp_r:4d} → ML FP={fp_m:4d}  "
              f"Reduction={data['fp_reduction_%']:5.1f}%")

    overall_reduction = (overall_fp_rule - overall_fp_ml) / (overall_fp_rule + 1e-9) * 100
    print(f"\n  ★ Overall FP reduction: {overall_reduction:.1f}%")

    print(f"\n  Top 5 priority alerts:")
    for i, alert in enumerate(queue[:5], 1):
        print(f"    {i}. [{alert.severity:8s}] {alert.src_ip:17s} | "
              f"{alert.layer:8s} | {alert.attack_type:25s} | "
              f"score={alert.ml_score:.3f} | TTPs={','.join(alert.mitre_ttps[:2])}")

    # Export
    Path("data").mkdir(exist_ok=True)
    alert_engine.export_alerts("data/alerts.jsonl")

    full_report = {
        "run_timestamp":   __import__("datetime").datetime.utcnow().isoformat(),
        "evaluation":      eval_report,
        "alert_statistics":stats,
        "campaigns":       campaigns,
        "overall_fp_reduction_%": round(overall_reduction, 1),
        "runtime_seconds": round(time.time() - t0, 2),
    }
    with open("data/full_report.json", "w") as f:
        json.dump(full_report, f, indent=2, default=str)

    print(f"\n  Full report saved  → data/full_report.json")
    print(f"  Runtime: {time.time()-t0:.1f}s")
    print("\n╔══════════════════════════════════════════════════╗")
    print("║  Pipeline complete. System ready for SOC use.   ║")
    print("╚══════════════════════════════════════════════════╝\n")

    return full_report


if __name__ == "__main__":
    main()
