import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.model_selection import train_test_split
from google.colab import files

print("==================================================")
print(" STEP 1: FILE UPLOAD (100% Dataset)")
print("==================================================")
print("Niche 'Choose Files' button par click karke apni file upload karein:\n")

# File upload pop-up
uploaded = files.upload()

# File name fetch karein
filename = list(uploaded.keys())[0]
print(f"\n✓ File Successfully Uploaded: {filename}\n")

# JSON, CSV ya Excel read karne ka system
if filename.endswith('.json'):
    try:
        df = pd.read_json(filename)
    except ValueError:
        # Structured / Nested JSON Logs ke liye lines=True
        df = pd.read_json(filename, lines=True)
elif filename.endswith('.csv'):
    df = pd.read_csv(filename)
elif filename.endswith(('.xls', '.xlsx')):
    df = pd.read_excel(filename)
else:
    raise ValueError("File format supported nahi hai. CSV, JSON ya Excel upload karein.")

print(f"Total Rows: {df.shape[0]} | Total Columns: {df.shape[1]}")

print("\n==================================================")
print(" STEP 2: TIMESTAMP / DATE UPDATING")
print("==================================================")

# Existing date/time columns update karna
updated_cols = []
for col in df.columns:
    if any(keyword in str(col).lower() for keyword in ['date', 'time', 'timestamp', 'year', 'created', 'log_time']):
        try:
            df[col] = pd.to_datetime(df[col])
            updated_cols.append(col)
        except Exception:
            pass

# Recent timestamp column add karna
df['last_updated_timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

print(f"✓ Automatically processed date/time columns: {updated_cols if updated_cols else 'None detected'}")
print("✓ Added new column: 'last_updated_timestamp' (Current Recent Time)")

print("\n==================================================")
print(" STEP 3: DATASET ATTRIBUTES DESCRIPTION (One-Liners)")
print("==================================================")

for col in df.columns:
    dtype = df[col].dtype
    n_unique = df[col].nunique()
    n_null = df[col].isnull().sum()
    
    if pd.api.types.is_numeric_dtype(dtype):
        min_v, max_v = df[col].min(), df[col].max()
        desc = f"Numeric Column — Values range from {min_v} to {max_v} ({n_unique} unique values, {n_null} nulls)."
    elif pd.api.types.is_datetime64_any_dtype(dtype):
        desc = f"Date/Time Column — Spans from {df[col].min()} to {df[col].max()}."
    else:
        sample_vals = ", ".join([str(x) for x in df[col].dropna().unique()[:3]])
        desc = f"Categorical/Text Column — Examples: [{sample_vals}] ({n_unique} unique categories, {n_null} nulls)."
    
    print(f"• {col} ({dtype}): {desc}")

print("\n==================================================")
print(" STEP 4: 80% / 20% SPLIT & AUTO-DOWNLOAD")
print("==================================================")

# 80% aur 20% split
train_df, test_df = train_test_split(df, test_size=0.20, random_state=42)

# SSH logs JSON data ko clean CSV formats mein export karenge
train_filename = "SSH_Logs_80_percent.csv"
test_filename = "SSH_Logs_20_percent.csv"

train_df.to_csv(train_filename, index=False)
test_df.to_csv(test_filename, index=False)

print(f"✓ 80% Dataset Created: '{train_filename}' ({len(train_df)} rows)")
print(f"✓ 20% Dataset Created: '{test_filename}' ({len(test_df)} rows)")
print("\nDono split files (.csv) aap ke browser mein auto-download ho rahi hain...")

# Auto-download files
files.download(train_filename)
files.download(test_filename)

