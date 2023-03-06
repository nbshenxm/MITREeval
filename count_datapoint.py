import os
import json

def count_datapoints(json_obj):
    count = 0
    if isinstance(json_obj, dict):
        for key in json_obj:
            count += 1
            count += count_datapoints(json_obj[key])
    elif isinstance(json_obj, list):
        for item in json_obj:
            count += 1
            count += count_datapoints(item)
    else:
        count += 1
    return count

folder_path = "json/"
total_datapoints = 0

for root, dirs, files in os.walk(folder_path):
    for file in files:
        if file.endswith(".json"):
            file_path = os.path.join(root, file)
            with open(file_path, "r") as f:
                json_obj = json.load(f)
                datapoints = count_datapoints(json_obj)
                print(f"{file_path}: {datapoints} datapoints")
                total_datapoints += datapoints

print(f"Total datapoints: {total_datapoints}")
