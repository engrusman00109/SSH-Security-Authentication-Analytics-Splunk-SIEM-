import io
import random
from datetime import datetime, timedelta
from google.colab import files
import numpy as np
import pandas as pd

# ---------------------------------------------------------
# STEP 1: Upload your 20% CSV File
# ---------------------------------------------------------
print("Please upload your 20% SSH Dataset CSV file:")
uploaded = files.upload()

file_name = list(uploaded.keys())[0]
df = pd.read_csv(io.BytesIO(uploaded[file_name]))
n = len(df)
print(f"\nSuccessfully loaded '{file_name}' with {n} rows.")

# ---------------------------------------------------------
# STEP 2: Randomize Timestamps (Between July 1, 2026 & August 1, 2026)
# ---------------------------------------------------------
start_date = datetime(2026, 7, 1, 0, 0, 0)
end_date = datetime(2026, 8, 1, 23, 59, 59)
total_seconds = int((end_date - start_date).total_seconds())

random_timestamps = []
for _ in range(n):
    rand_sec = random.randint(0, total_seconds)
    dt = start_date + timedelta(seconds=rand_sec)
    random_timestamps.append(dt)

# Sort timestamps (optional: keeps logs chronologically sorted)
random_timestamps.sort()

for i in range(n):
    dt = random_timestamps[i]
    df.at[i, "ts"] = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    if "last_updated_timestamp" in df.columns:
        df.at[i, "last_updated_timestamp"] = dt.strftime("%Y-%m-%d %H:%M:%S")

# ---------------------------------------------------------
# STEP 3: Inject Specific Conditions to Trigger ALL 10 Alerts
# ---------------------------------------------------------

# Alert 01: SSH Brute-Force (>= 5 failed attempts from single IP)
for r in range(0, 6):
    df.at[r, "id.orig_h"] = "198.51.100.50"
    df.at[r, "auth_success"] = 0.0
    df.at[r, "auth_attempts"] = 1
    df.at[r, "event_type"] = "Failed SSH Login"
    df.at[r, "conn_state"] = "SF"

# Alert 02: Root Account Targeting
for r in [6, 7, 45, 85]:
    df.at[r, "username"] = "root"
    df.at[r, "event_type"] = "Failed SSH Login"
    df.at[r, "auth_success"] = 0.0
    df.at[r, "auth_attempts"] = 1

# Alert 03: High Auth Attempts Anomaly (> 3 attempts)
for r in [8, 9, 46, 86]:
    df.at[r, "auth_attempts"] = 5
    df.at[r, "event_type"] = "Multiple Failed Authentication Attempts"
    df.at[r, "auth_success"] = 0.0

# Alert 04: Unusual Nighttime Access (Between 00:00 and 05:00 AM)
for r in range(10, 15):
    night_dt = datetime(
        2026,
        7,
        random.randint(2, 30),
        random.randint(0, 4),
        random.randint(0, 59),
    )
    df.at[r, "ts"] = night_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    if "last_updated_timestamp" in df.columns:
        df.at[r, "last_updated_timestamp"] = night_dt.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

# Alert 05: Password Spraying Attack (> 3 distinct usernames from single IP)
spray_users = ["root", "admin", "oracle", "svc_ssh", "postgres"]
for idx, u in zip(range(15, 20), spray_users):
    df.at[idx, "id.orig_h"] = "203.0.113.88"
    df.at[idx, "username"] = u
    df.at[idx, "auth_success"] = 0.0
    df.at[idx, "auth_attempts"] = 1
    df.at[idx, "event_type"] = "Failed SSH Login"

# Alert 06: SSH Login Success After Failures (Same IP + Username)
for r in [20, 21, 22]:
    df.at[r, "id.orig_h"] = "192.0.2.77"
    df.at[r, "username"] = "sysadmin_victim"
    df.at[r, "auth_success"] = 0.0
    df.at[r, "event_type"] = "Failed SSH Login"
    df.at[r, "auth_attempts"] = 1

df.at[23, "id.orig_h"] = "192.0.2.77"
df.at[23, "username"] = "sysadmin_victim"
df.at[23, "auth_success"] = 1.0
df.at[23, "event_type"] = "Successful SSH Login"
df.at[23, "auth_attempts"] = 4

# Alert 07: High Packet Count (> 800 packets)
for r, pkts in zip([24, 25, 50, 90], [950, 1200, 1500, 850]):
    df.at[r, "orig_pkts"] = pkts
    df.at[r, "orig_ip_bytes"] = pkts * 64

# Alert 08: Admin/Service Account Access Attempt
admin_users = ["admin", "webmaster", "dbadmin", "backup"]
for idx, u in zip(range(26, 30), admin_users):
    df.at[idx, "username"] = u

# Alert 09: Non-Authenticated SSH Connection Anomaly (conn_state != SF)
conn_states = ["REJ", "S0", "RSTO"]
for idx, cs in zip(range(30, 33), conn_states):
    df.at[idx, "conn_state"] = cs
    df.at[idx, "event_type"] = "Connection Without Authentication"
    df.at[idx, "auth_success"] = np.nan
    df.at[idx, "auth_attempts"] = 0

# Alert 10: Distributed SSH Connection Activity (>= 10 unique IPs targeting 1 server)
target_server = "10.10.50.100"
for idx, i_ip in enumerate(range(33, 45)):
    df.at[i_ip, "id.resp_h"] = target_server
    df.at[i_ip, "id.orig_h"] = f"198.51.100.{101 + idx}"

# ---------------------------------------------------------
# STEP 4: Export & Download Ready CSV
# ---------------------------------------------------------
output_file = "SSH_Logs_20_percent_Testing_Ready.csv"
df.to_csv(output_file, index=False)
print(
    f"\nDataset processing complete! Modified file saved as '{output_file}'."
)
files.download(output_file)