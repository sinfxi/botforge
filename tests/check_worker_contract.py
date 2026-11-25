from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src" / "index.js").read_text(encoding="utf-8")

def require(condition, message):
    if not condition:
        raise AssertionError(message)

def main():
    require(SOURCE.count('CREATE TABLE IF NOT EXISTS ncoin_project_rewards') >= 2,
            "Both Telegram and website approval paths must initialize the idempotent reward ledger")
    require(SOURCE.count("INSERT OR IGNORE INTO ncoin_project_rewards(submission_id,user_id,amount) SELECT ?,?,100 WHERE changes()=1") == 2,
            "Both approval paths must gate the 100-coin reward on a newly approved submission")
    require(SOURCE.count("INSERT INTO ncoin_transactions(id,user_id,amount,kind,description) SELECT ?,?,100,'project_approved'") == 2,
            "Both approval paths must write the reward transaction atomically")
    require(SOURCE.count("UPDATE submissions SET status='approved',reviewed_by=?,reviewed_at=? WHERE id=? AND status='pending'") >= 2,
            "Both approval paths must use a conditional pending-to-approved transition")
    require('path === "/api/community/leaderboard" && method === "GET"' in SOURCE,
            "Creator leaderboard API route is missing")
    require('commandName === "/top" || userAction === "🏆 برترین سازندگان"' in SOURCE,
            "Telegram leaderboard command/button handler is missing")
    require('{command:"top",description:"رتبه‌بندی سازندگان"}' in SOURCE,
            "Telegram /top command must be registered with setMyCommands")

    keyboard = SOURCE.split("const TELEGRAM_USER_MENU_KEYBOARD =", 1)[1].split("function json", 1)[0]
    buttons = re.findall(r'text:"([^"]+)"', keyboard)
    duplicates = sorted({button for button in buttons if buttons.count(button) > 1})
    require(not duplicates, "Persistent Telegram keyboard contains duplicate buttons: " + ", ".join(duplicates))
    require("is_persistent:true" in keyboard and "resize_keyboard:true" in keyboard,
            "Persistent Telegram keyboard flags are missing")
    print("worker contracts: OK (atomic 100-coin approval, leaderboard, Telegram menu)")

if __name__ == "__main__":
    main()
