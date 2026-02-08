import streamlit as st
import qrcode
import time
import hashlib
from datetime import datetime
import pandas as pd
import os

# --- CONFIGURATION ---
SECRET_SALT = "research_dev_2026" 
REFRESH_RATE = 60  # Increased to 30s for better reliability in class
LOG_FILE = "attendance_log.csv"

def get_valid_tokens():
    """Generates the current and previous token to prevent 'Expired' errors due to lag."""
    current_interval = int(time.time() // REFRESH_RATE)
    # Current Token
    t1 = hashlib.sha256(f"{current_interval}{SECRET_SALT}".encode()).hexdigest()[:8]
    # Previous Token (allows a 30s grace period)
    t2 = hashlib.sha256(f"{current_interval - 1}{SECRET_SALT}".encode()).hexdigest()[:8]
    return [t1, t2]

def get_remote_ip():
    """Retrieves the student's IP address."""
    try:
        return st.context.headers.get("X-Forwarded-For", "Unknown")
    except:
        return "Local/Unknown"

def main():
    st.set_page_config(page_title="Secure Attendance", layout="centered")
    
    # Ensure log file exists
    if not os.path.exists(LOG_FILE):
        pd.DataFrame(columns=["Name", "ID", "Timestamp", "IP", "Token"]).to_csv(LOG_FILE, index=False)

    # Instructor Sidebar
    is_admin = st.sidebar.toggle("Instructor Mode")

    if is_admin:
        st.header("Admin Dashboard")
        tokens = get_valid_tokens()
        current_token = tokens[0]
        
        # Replace the URL below with your actual Streamlit App URL
        # Example: https://attendance-tracker.streamlit.app/
        base_url = "https://blank-app-170h3hh4z91.streamlit.app/"
        full_url = f"{base_url}?token={current_token}"
        
        # Display QR
        qr = qrcode.make(full_url)
        qr.save("current_qr.png")
        st.image("current_qr.png", caption=f"QR refreshes every {REFRESH_RATE} seconds")
        
        # Stats
        df = pd.read_csv(LOG_FILE)
        st.metric("Students Checked In", len(df))
        st.dataframe(df)
        st.download_button("Export CSV", df.to_csv(index=False), "attendance.csv", "text/csv")

    else:
        # Student View
        st.header("Student Check-in")
        token_from_url = st.query_params.get("token")
        valid_tokens = get_valid_tokens()
        student_ip = get_remote_ip()

        # SUCCESS: Token is valid (current or just expired)
        if token_from_url in valid_tokens:
            with st.form("attendance_form", clear_on_submit=True):
                name = st.text_input("Full Name")
                s_id = st.text_input("Student ID")
                submit = st.form_submit_button("Submit Attendance")

                if submit:
                    df = pd.read_csv(LOG_FILE)
                    
                    # Security Checks
                    is_duplicate_ip = (df['IP'] == student_ip).any()
                    is_duplicate_id = (df['ID'].astype(str) == str(s_id)).any()

                    if is_duplicate_id:
                        st.error("This Student ID has already been recorded.")
                    elif is_duplicate_ip and student_ip != "Unknown":
                        st.warning("⚠️ This device has already submitted attendance.")
                    elif not name or not s_id:
                        st.error("Please fill in both fields.")
                    else:
                        new_data = {
                            "Name": [name], "ID": [s_id], 
                            "Timestamp": [datetime.now().strftime("%H:%M:%S")],
                            "IP": [student_ip], "Token": [token_from_url]
                        }
                        pd.DataFrame(new_data).to_csv(LOG_FILE, mode='a', header=False, index=False)
                        st.success("Verified! You can now close this tab.")
        else:
            st.error("Invalid or Expired Link. Please scan the QR code currently on the screen.")

if __name__ == "__main__":
    main()
