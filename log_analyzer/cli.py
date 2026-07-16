import argparse
import json
import sys

from .analyzer import LogAnalyzer

def main():
    parser = argparse.ArgumentParser(
        description="ThreatLens - Lightweight Web Log Anomaly Detector",
        epilog="Analyzes standard Nginx/Apache access logs for common attack patterns."
    )

    parser.add_argument(
        "logfile",
        help="Path to the access log file to analyze."
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format for the report (default: text)."
    )

    args = parser.parse_args()

    analyzer = LogAnalyzer()

    try:
        analyzer.analyze_file(args.logfile)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

    summary = analyzer.get_summary()

    if args.format == "json":
        print(json.dumps(summary, indent=4))
    else:
        print("="*50)
        print(" ThreatLens - Analysis Report")
        print("="*50)
        print(f"Total Log Lines Parsed:     {summary['total_lines_parsed']}")
        print(f"Total Attacks Detected:     {summary['total_attacks_detected']}")
        print(f"Unique Malicious IPs:       {summary['unique_malicious_ips_count']}")
        print("="*50)

        if summary['unique_malicious_ips_count'] > 0:
            print("\nMalicious Activity Summary:\n")
            for ip, activities in summary['malicious_activity_by_ip'].items():
                print(f"[-] IP Address: {ip} (Events: {len(activities)})")
                # Show up to first 3 events per IP for brevity
                for activity in activities[:3]:
                    print(f"    -> [{activity['timestamp']}] {activity['attack_type']} - {activity['method']} {activity['path']} (Status: {activity['status']})")
                if len(activities) > 3:
                    print(f"    -> ... and {len(activities) - 3} more events.")
                print()
        else:
            print("\nNo malicious activity detected.")
            print("="*50)

if __name__ == "__main__":
    main()
