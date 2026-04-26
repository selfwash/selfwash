import os
from dotenv import load_dotenv
from iot_service import start_machine

# טעינת המפתחות מקובץ ה-.env
load_dotenv()


def run_test():
    # המספר הסידורי האמיתי של המכונה שלך
    TEST_DEVICE_SN = "S251112H06"
    PREPAY_AMOUNT = 10.0  # ננסה להטעין 10 שקלים

    print(f"🔄 מתחיל ניסיון הפעלה למכונה {TEST_DEVICE_SN}...")
    print(f"💰 סכום טעינה: {PREPAY_AMOUNT} ₪")
    print(f"🌐 שרת יעד: {os.getenv('IOT_BASE_URL')}")
    print("-" * 30)

    try:
        response = start_machine(TEST_DEVICE_SN, PREPAY_AMOUNT)
        print("✅ הצלחה! התשובה מהשרת:")
        print(response)
    except Exception as e:
        print("❌ שגיאה בהפעלה:")
        print(e)


if __name__ == "__main__":
    run_test()
