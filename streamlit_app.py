import streamlit as st
import qrcode
import time
import hashlib
from datetime import datetime
import pandas as pd
import os

# --- CONFIGURATION ---
SECRET_SALT = "research_dev_2026" 
REFRESH_RATE = 30  # Refresh interval in seconds
LOG_FILE = "attendance_log.csv"

def get_valid_tokens():
    """Generates the current and previous token to account for network lag."""
    current_interval = int(time.time() // REFRESH_RATE)
    t1 = hashlib.sha256(f"{current_interval}{SECRET_SALT}".encode()).hexdigest()[:8]
    t2 = hashlib.sha256(f"{current_interval - 1}{SECRET_SALT}".encode()).hexdigest()[:8]
    return [t1, t2]

def get_remote_ip():
    """Retrieves the student's IP address from headers."""
    try:
        return st.context.headers.get("X-Forwarded-For", "Unknown")
    except:
        return "Local/Unknown"

def main():
    st.set_page_config(page_title="Live Secure Attendance", layout="wide")
    
    # Initialize log file
    if not os.path.exists(LOG_FILE):
        pd.DataFrame(columns=["Name", "ID", "Timestamp", "IP", "Token"]).to_csv(LOG_FILE, index=False)

    # Instructor Sidebar
    is_admin = st.sidebar.toggle("Instructor Mode (Project this)")

    if is_admin:
        st.sidebar.warning("⚠️ Data is temporary. Download CSV before closing!")
        
        # --- ADMIN DASHBOARD ---
        col1, col2 = st.columns([1, 2])
        
        with col1:
            st.header("Scan to Check-in")
            tokens = get_valid_tokens()
            current_token = tokens[0]
            
            # UPDATE THIS with your actual app URL
            base_url = "https://blank-app-170h3hh4z91.streamlit.app/"
            full_url = f"{base_url}?token={current_token}"
            
            qr = qrcode.make(full_url)
            qr.save("current_qr.png")
            st.image("current_qr.png", caption=f"Refreshing in {REFRESH_RATE}s")
            st.write(f"**Current Token:** `{current_token}`")

        with col2:
            st.header("Live Attendance List")
            df = pd.read_csv(LOG_FILE)
            st.metric("Total Present", len(df))
            st.dataframe(df, use_container_width=True, height=400)
            
            if st.download_button("📥 Download Final CSV", df.to_csv(index=False), "attendance.csv", "text/csv"):
                st.balloons()

        # THE HEARTBEAT: Auto-refresh the page
        time.sleep(REFRESH_RATE)
        st.rerun()

    else:
        # --- STUDENT VIEW ---
        st.header("Student Check-in")
        token_from_url = st.query_params.get("token")
        valid_tokens = get_valid_tokens()
        student_ip = get_remote_ip()

        if token_from_url in valid_tokens:
            with st.form("checkin_form", clear_on_submit=True):
                name = st.text_input("Full Name")
                s_id = st.text_input("Student ID")
                submit = st.form_submit_button("Submit Attendance")

                if submit:
                    df = pd.read_csv(LOG_FILE)
                    
                    # Duplicate checks
                    is_dup_id = (df['ID'].astype(str) == str(s_id)).any()
                    is_dup_ip = (df['IP'] == student_ip).any()

                    if is_dup_id:
                        st.error("This Student ID has already been recorded.")
                    elif is_dup_ip and student_ip != "Unknown":
                        st.warning("⚠️ Only one submission allowed per device.")
                    elif not name or not s_id:
                        st.error("Please provide both Name and ID.")
                    else:
                        new_row = pd.DataFrame([{
                            "Name": name, "ID": s_id, 
                            "Timestamp": datetime.now().strftime("%H:%M:%S"),
                            "IP": student_ip, "Token": token_from_url
                        }])
                        new_row.to_csv(LOG_FILE, mode='a', header=False, index=False)
                        st.success("✅ Attendance marked! You may close this tab.")
        else:
            st.error("❌ Invalid or Expired Link. Please scan the QR code currently on the screen.")

if __name__ == "__main__":
    main()
