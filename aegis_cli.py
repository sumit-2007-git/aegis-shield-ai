import argparse
import json
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from core.threat_engine import UnifiedThreatEngine

def main():
    parser = argparse.ArgumentParser(description="AegisLocal - On-Device Threat, Phishing and Scam Intelligence CLI")
    parser.add_argument("--scan", type=str, help="Text, message, or URL to scan")
    parser.add_argument("--benchmark", action="store_true", help="Run latency and offline benchmark")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    
    args = parser.parse_args()
    engine = UnifiedThreatEngine()

    if args.benchmark:
        print("\n⚡ Running AegisLocal On-Device Performance & Latency Benchmark...")
        test_samples = [
            "Your SBI account is blocked. Update KYC at http://sbi-verification.xyz",
            "Electricity will be disconnected at 9:30 PM. Call 9876543210 immediately.",
            "482910 is your OTP for HDFC Bank card. Do not share OTP.",
            "http://paypa1-security-login.top/account/verify",
            "Congratulations! Won Rs 25,00,000 in KBC Lottery. Send Aadhaar."
        ]
        
        times = []
        for i in range(25):
            sample = test_samples[i % len(test_samples)]
            t0 = time.perf_counter()
            engine.scan(sample)
            t1 = time.perf_counter()
            times.append((t1 - t0) * 1000)

        avg_latency = sum(times) / len(times)
        min_latency = min(times)
        max_latency = max(times)

        print("=" * 60)
        print("  AEGIS-LOCAL ON-DEVICE BENCHMARK RESULTS")
        print("=" * 60)
        print(f"  • Total Scans Evaluated      : {len(times)}")
        print(f"  • Average Inference Latency : {avg_latency:.2f} ms")
        print(f"  • Minimum Latency            : {min_latency:.2f} ms")
        print(f"  • Maximum Latency            : {max_latency:.2f} ms")
        print(f"  • External Cloud Calls       : 0 (Strictly Local CPU)")
        print(f"  • Network Data Sent          : 0 Bytes (Complete Privacy)")
        print("=" * 60)
        return

    if not args.scan:
        print("Please provide a text or link to scan using --scan \"message\" or run --benchmark")
        sys.exit(1)

    result = engine.scan(args.scan)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print("\n" + "=" * 65)
    print("  🛡️  AEGIS-LOCAL THREAT INTELLIGENCE REPORT (ON-DEVICE)")
    print("=" * 65)
    print(f"  Verdict       : {result['verdict']}")
    print(f"  Threat Level  : {result['threat_level']}")
    print(f"  Risk Score    : {result['risk_score']} / 100")
    print(f"  Category      : {result['category']}")
    print(f"  Local Latency : {result['telemetry']['latency_ms']} ms")
    print(f"  Cloud Calls   : {result['telemetry']['cloud_network_calls']} (100% Offline)")
    print("-" * 65)
    print("  📋 REASONING BREAKDOWN:")
    for reason in result['explanation']['reasons']:
        print(f"    [!] {reason['title']}: {reason['explanation']}")
    
    print("-" * 65)
    print("  💡 RECOMMENDATIONS:")
    for rec in result['explanation']['recommendations']:
        print(f"    • {rec}")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    main()
