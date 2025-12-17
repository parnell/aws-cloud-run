#! /usr/bin/env python3
import os
import sys

print(f"Python version: {sys.version}")
print("Hello, World!")
for arg in sys.argv:
    print(f"Argument: {arg}")
for key, value in os.environ.items():
    print(f"Environment variable: {key} = {value}")
