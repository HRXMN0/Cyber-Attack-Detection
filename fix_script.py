"""fix_script.py — patches the broken JS template literal in script.js"""
import re

path = "static/script.js"

with open(path, "r", encoding="utf-8") as f:
    lines = f.readlines()

print(f"Total lines: {len(lines)}")

# Find the problematic line by its unique content
target_marker = "sev==='critical'?'255,23,68'"
fix_start = None
for i, line in enumerate(lines):
    if target_marker in line:
        fix_start = i
        print(f"Found bad line at 1-based line {i+1}: {repr(line[:80])}")
        break

if fix_start is None:
    print("ERROR: target line not found!")
    exit(1)

# We need to replace lines from `card.style.cssText = \`` up to closing backtick
# The block is: lines[fix_start-2 .. fix_start+9]
# Let's find the start of `card.style.cssText = \``
ctx_start = fix_start - 2  # two lines before the bad rgba line
# Find exact line that starts the block
for i in range(fix_start, fix_start-6, -1):
    if "card.style.cssText" in lines[i]:
        ctx_start = i
        break

# Find the closing backtick line
ctx_end = fix_start
for i in range(fix_start, min(fix_start+10, len(lines))):
    if lines[i].strip() == "`;" or lines[i].strip().endswith("`;"):
        ctx_end = i
        break

print(f"Replacing lines {ctx_start+1} to {ctx_end+1}")
print("Old block:")
for l in lines[ctx_start:ctx_end+1]:
    print(" ", repr(l.rstrip()))

# Build replacement — safe string concatenation, no template literal
replacement = (
    "    const _bg = sev === 'critical' ? '255,23,68' : sev === 'high' ? '255,109,0' : '0,229,255';\n"
    "    card.style.cssText = 'background:rgba(' + _bg + ',0.05);border:1px solid ' + clr + '33;"
    "border-left:3px solid ' + clr + ';border-radius:10px;padding:10px 12px;"
    "cursor:pointer;transition:.2s;animation:blockIn .35s ease;flex-shrink:0;';\n"
)

lines[ctx_start:ctx_end+1] = [replacement]

with open(path, "w", encoding="utf-8") as f:
    f.writelines(lines)

print(f"\nDone. File saved. New total lines: {len(lines)}")
