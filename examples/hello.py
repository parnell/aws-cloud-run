#! /usr/bin/env python3
import sys

print(f"Python version: {sys.version}")
print("Hello, World!")
for arg in sys.argv:
    print(f"Argument: {arg}")
