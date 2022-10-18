#!/bin/bash

# python3 get_results.py

pip3 install -r requirements.txt

python3 mitre_eval.py

python3 host.py $1