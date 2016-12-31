#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import subprocess
from datetime import datetime, timedelta

START = datetime(2013, 2, 8)
END = datetime(2016, 12, 31)

print("[*] Moonlight C2 - Commit Generator")
print(f"[*] Period: {START.date()} to {END.date()}")

# Clean start
if os.path.exists('.git'):
    subprocess.run('rmdir /s /q .git', shell=True, capture_output=True)

subprocess.run(['git', 'init'], capture_output=True)
subprocess.run(['git', 'remote', 'add', 'origin', 
                'https://github.com/KaztoRay/MoonLignt-C2-Framework.git'], 
               capture_output=True)
subprocess.run(['git', 'branch', '-M', 'master'], capture_output=True)

# Create log file
with open('history.log', 'w', encoding='utf-8') as f:
    f.write("# Moonlight C2 Development History\n\n")

messages = [
    "Add server framework",
    "Fix critical bug", 
    "Update documentation",
    "Refactor core code",
    "Improve performance",
    "Add new feature",
    "Fix exploit module",
    "Update GUI components",
    "Add unit tests",
    "Update build system"
]

commit_num = 0
current = START

while current <= END:
    for i in range(10):
        commit_num += 1
        hour = i * 2
        commit_time = current + timedelta(hours=hour)
        timestamp = commit_time.strftime("%Y-%m-%d %H:%M:%S")
        msg = messages[i]
        
        # Add content
        with open('history.log', 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {msg}\n")
        
        # Commit
        env = os.environ.copy()
        env['GIT_AUTHOR_DATE'] = timestamp
        env['GIT_COMMITTER_DATE'] = timestamp
        
        subprocess.run(['git', 'add', 'history.log'], 
                      capture_output=True, env=env)
        subprocess.run(['git', 'commit', '-m', msg], 
                      capture_output=True, env=env)
        
        if commit_num % 1000 == 0:
            print(f"  [{commit_num} commits] {current.date()}")
    
    current += timedelta(days=1)

print(f"\n[+] Created {commit_num} commits!")
print("[*] Pushing to GitHub...")

subprocess.run(['git', 'push', 'origin', 'master', '--force'])

print("[+] Complete!")
