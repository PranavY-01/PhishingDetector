from analyzer import analyze_email
from utils import load_eml_file

def main():
    print(" Phishing Email Detector ")
    filepath = input("Enter path to .eml file: ").strip()
    
    try:
        raw_email = load_eml_file(filepath)
        result = analyze_email(raw_email)
        
        print("\n📄 Analysis Result")
        print("-" * 40)
        print("Risk Score:", result['score'])
        print("Verdict:", result['verdict'])
        print("Findings:")
        for flag in result['flags']:
            print("  -", flag)
    except Exception as e:
        print("❌ Error:", e)

if __name__ == "__main__":
    main()
