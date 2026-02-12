# generate_sigma_lolbas.py
import sys

file_path = "/home/remy/Desktop/Github/death/sigma/windows/LOLBAS/experimental/lolbas_binary.txt"  # Update if path is different

with open(file_path, "r") as f:
    binaries = [line.strip() for line in f if line.strip()]

# Format as YAML list with proper indentation
yaml_lines = ["        - '\\{}'".format(b) for b in binaries]

# Output ready to paste into Sigma
print("bin:")
print("    Image|endswith:")
for line in yaml_lines:
    print(line)
print("condition: bin and cmdline_ipv4")
