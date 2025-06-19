import requests
import base64
import time

def scan_url_with_virustotal(url):
    api_key = "Virus Tool API key" # ← Yahan apna VirusTotal API key paste karo
    headers = {"x-apikey": api_key}
    
    # Step 1: Submit the URL for scanning
    print("🔄 Submitting URL for analysis...")
    submit_response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    if submit_response.status_code != 200:
        print("❌ Error submitting URL:", submit_response.status_code)
        return

    analysis_id = submit_response.json()["data"]["id"]

    # Step 2: Wait a few seconds then fetch the result
    print("⏳ Waiting for results...")
    time.sleep(10) # optional delay for analysis to complete

    result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    result_response = requests.get(result_url, headers=headers)

    if result_response.status_code != 200:
        print("❌ Error fetching results:", result_response.status_code)
        return

    stats = result_response.json()["data"]["attributes"]["stats"]
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    # Step 3: Show result
    print("\n📊 Scan Results:")
    print(f"🦠 Malicious detections: {malicious}")
    print(f"❓ Suspicious detections: {suspicious}")

    if malicious > 0 or suspicious > 0:
        print("⚠️ Verdict: This URL may be dangerous.")
    else:
        print("✅ Verdict: This URL appears to be safe.")

if __name__ == "__main__":
    print("🔐 Phish Checker CLI - Powered by VirusTotal")
    user_url = input("🌐 Enter a URL to scan: ").strip()
    if user_url:
        scan_url_with_virustotal(user_url)
    else:
        print("❌ Please enter a valid URL.")
