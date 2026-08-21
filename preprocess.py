import pandas as pd

# Load the dataset
data = pd.read_csv("data/network_data.csv")

print("===== ORIGINAL DATA =====")
print(data)

# Check missing values
print("\n===== MISSING VALUES =====")
print(data.isnull().sum())

# Remove rows with missing values
data = data.dropna()

# Features that will be given to the ML model
features = [
    "flow_duration",
    "packet_count",
    "byte_count",
    "port"
]

ml_data = data[features]

print("\n===== ML-READY DATA =====")
print(ml_data)

print("\nNumber of records:", len(ml_data))
print("Number of features:", len(features))