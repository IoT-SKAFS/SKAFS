#!/bin/bash

# Set the name of the Python script you want to run
python_script="SKAFS_client_IoT.py"

# Set the name of the log file
log_file="output.log"

python_args="-c 192.168.88.254"

# Loop 100 times and run the Python script, appending the output to the log file
for i in {1..100}; do
    echo "Running iteration $i..."
    python "$python_script" $python_args >> "$log_file"
done

echo "Done."