with open("Linux_2k.log", "r", encoding="utf-8") as file:
    Logs = file.readlines()

subset_logs = Logs[199:500] 


suspicious_entries = []
for line in subset_logs:
   if "Failed password" in line:
     suspicious_entries.append(("Failed Login", line.strip()))
   elif "authentication failure" in line:
     suspicious_entries.append(("Auth Failure", line.strip()))
   elif "user unknown" in line or "invalid user" in line:

    suspicious_entries.append(("Unknown User", line.strip()))

print("=== Suspicious Log Entries (Lines 200–500) ===")
for entry_type, entry in suspicious_entries:
  print(f"[{entry_type}] {entry}")

print(f"\nTotal  suspicious entries found:{len(suspicious_entries)}")


import csv
with open("suspicious_logs.csv", "w", newline="") as csvfile:

    writer = csv.writer(csvfile)
    writer.writerow(["Type", "Log Entry"])
    writer.writerows(suspicious_entries)
print("Results saved to suspicious_logs.csv")