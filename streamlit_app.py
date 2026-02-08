import streamlit as st
import qrcode
import time
import hashlib
from datetime import datetime
import pandas as pd
import os

# --- CONFIGURATION ---
SECRET_SALT = "research_dev_2026" 
REFRESH_RATE = 15  # Slightly longer for 60+ students to scan
LOG_FILE = "attendance_log.csv"

def generate_token():
    """Generates a time-based token."""
    current_interval = int(time.time() // REFRESH_RATE)
    return hashlib.sha256(f"{current_interval}{SECRET_SALT}".encode()).hexdigest()[:8]

def get_remote_ip():
    """Retrieves the student's IP address from Streamlit headers."""
    # This works when deployed on Streamlit Cloud or behind most proxies
    try:
        return st.context.headers.get("X-Forwarded-For", "Unknown")
    except:
        return "Local/Unknown"

def main():
    st.set_page_config(page_title="Secure Attendance", layout="centered")
    
    # Initialize log file if it doesn't exist
    if not os.path.exists(LOG_FILE):
        pd.DataFrame(columns=["Name", "ID", "Timestamp", "IP", "Token"]).to_csv(LOG_FILE, index=False)

    # Instructor Sidebar
    is_admin = st.sidebar.toggle("Instructor Mode")

    if is_admin:
        st.header("Admin Dashboard")
        token = generate_token()
        
        # Replace with your actual deployment URL
        url = f"https://your-app-name.streamlit.app/?token={token}"
        
        # Display QR
        qr = qrcode.make(url)
        qr.save("current_qr.png")
        st.image("current_qr.png", caption=f"QR refreshes every {REFRESH_RATE} seconds")
        
        # Real-time Stats
        df = pd.read_csv(LOG_FILE)
        st.metric("Students Checked In", len(df))
        
        if st.checkbox("Show Attendance Table"):
            st.dataframe(df)
            
        st.download_button("Export CSV", df.to_csv(index=False), "attendance.csv", "text/csv")

    else:
        # Student View
        st.header("Student Check-in")
        token_from_url = st.query_params.get("token")
        expected_token = generate_token()
        student_ip = get_remote_ip()

        if token_from_url == expected_token:
            with st.form("attendance_form", clear_on_submit=True):
                name = st.text_input("Full Name")
                s_id = st.text_input("Student ID")
                submit = st.form_submit_button("Submit Attendance")

                if submit:
                    df = pd.read_csv(LOG_FILE)
                    
                    # IP & ID Validation
                    is_duplicate_ip = (df['IP'] == student_ip).any()
                    is_duplicate_id = (df['ID'].astype(str) == str(s_id)).any()

                    if is_duplicate_id:
                        st.error("This Student ID has already been recorded.")
                    elif is_duplicate_ip and student_ip != "Unknown":
                        st.warning("⚠️ This device has already submitted attendance. Only one submission per device allowed.")
                    else:
                        # Append new record
                        new_data = {
                            "Name": [name],
                            "ID": [s_id],
                            "Timestamp": [datetime.now().strftime("%H:%M:%S")],
                            "IP": [student_ip],
                            "Token": [token_from_url]
                        }
                        pd.DataFrame(new_data).to_csv(LOG_FILE, mode='a', header=False, index=False)
                        st.success("Attendance marked! You can now close this tab.")
        else:
            st.error("Invalid or Expired Link. Please scan the QR code currently on the screen.")

if __name__ == "__main__":
    main()
