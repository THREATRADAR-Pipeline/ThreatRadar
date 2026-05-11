import os
import sys
import time
import argparse
from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from models.anomaly_detector import AnomalyDetector
from data.elasticsearch_ingest import ingest_from_elasticsearch, update_documents_with_analysis
from pipeline.llm_analyzer import judge_ioc, batch_judge, _ml_tier_and_action

def run_production_pipeline(
    es_url: str = "http://elasticsearch:9200",
    es_source_index: str = "ti_ip,ti_url,ti_domain,ti_hash,ti_cve,ti_wallet,ti_ransomware",
    es_user: str = "",
    es_password: str = "",
    model_dir: str = "models",
    llm_max: int = 500,
    contamination: float = 0.05,
):

    print("=" * 60)
    print("  PRODUCTION THREAT INTELLIGENCE ANALYSIS PIPELINE")
    print("=" * 60)

    print(f"\n[STEP 1/4]  Ingesting ALL IOCs from Elasticsearch...")
    print(f"   ES URL  : {es_url}")
    print(f"   Index   : {es_source_index}")

    try:
        records = ingest_from_elasticsearch(
            es_url=es_url,
            index=es_source_index,
            max_docs=500000,
            es_user=es_user,
            es_password=es_password,
            verify_certs=False,
            cortex_analyzed_only=True,
        )
    except Exception as e:
        raise RuntimeError(f"Failed to ingest data: {e}") from e

    if not records:
        print("     No records found. Exiting.")
        return

    print(f"\n[STEP 2/4]  Loading saved anomaly detection model from {model_dir}...")
    detector = AnomalyDetector(model_dir=model_dir, contamination=contamination)
    try:
        detector.load()
        print(f"    Loaded existing model from {model_dir}")
    except Exception as exc:
        raise RuntimeError(
            f"Failed to load the saved model from {model_dir}. "
            "This production pipeline does not retrain the model; the saved artifacts must already exist."
        ) from exc

    print(f"\n[STEP 3/4]  Scoring {len(records)} IOCs with ML model...")
    all_records = detector.predict(records)

    flagged_count = sum(1 for r in all_records if r.get("poisoning_flagged"))
    total = len(all_records)
    print(f"   ML flagged {flagged_count} / {total} IOCs as anomalous ({flagged_count/total*100:.1f}%)")

    print(f"\n[STEP 4/4] Performing LLM semantic analysis...")

    final_results = batch_judge(all_records, max_items=llm_max, verbose=True)

    for ioc in final_results:
        fusion_obj = ioc.pop("fusion", None) or {}
        llm_obj    = ioc.pop("llm_semantic", None) or {}
        if fusion_obj:
            ioc.update(fusion_obj)

        ioc["llm_contradictions_found"] = llm_obj.get("contradictions_found", [])
        ioc["llm_coherence_reasoning"]  = llm_obj.get("coherence_reasoning")
        ioc["llm_red_flags"]            = llm_obj.get("semantic_red_flags", [])
        ioc["llm_analyst_challenge"]    = llm_obj.get("analyst_challenge")

        if not ioc.get("analysis_ts"):
            ioc["analysis_ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    print(f"\n Updating {len(final_results)} documents in Elasticsearch...")
    try:
        update_documents_with_analysis(
            records=final_results,
            es_url=es_url,
            es_user=es_user,
            es_password=es_password,
            verify_certs=False,
        )
        print(f"   Successfully updated Elasticsearch in-place")
    except Exception as e:
        print(f"   Failed to update Elasticsearch: {e}")

    print("\n Pipeline complete!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Production TI Analysis Pipeline")
    parser.add_argument("--es-url", type=str, default=os.getenv("ELASTIC_HOST", "http://elasticsearch:9200"))
    parser.add_argument("--es-source-index", type=str, default=os.getenv("ES_SOURCE_INDEX", "ti_ip,ti_url,ti_domain,ti_hash,ti_cve,ti_wallet,ti_ransomware"))
    parser.add_argument("--es-user", type=str, default=os.getenv("ELASTIC_USER", ""))
    parser.add_argument("--es-password", type=str, default=os.getenv("ELASTIC_PASSWORD", ""))
    parser.add_argument("--llm-max", type=int, default=int(os.getenv("LLM_MAX", "500")))

    args = parser.parse_args()
    run_production_pipeline(
        es_url=args.es_url,
        es_source_index=args.es_source_index,
        es_user=args.es_user,
        es_password=args.es_password,
        llm_max=args.llm_max,
        contamination=float(os.getenv("CONTAMINATION_MAX", "0.05"))
    )
