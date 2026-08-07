import json, shutil, time, sys
from json import JSONDecoder

ALERT = 'C:/Users/chand/SentinetNet/shared/alerts.json'
TS = time.strftime('%Y%m%d%H%M%S')
BAK = ALERT + f'.bak.{TS}'
REPAIRED = ALERT + f'.repaired.{TS}'

print('Backing up', ALERT, '->', BAK)
shutil.copy2(ALERT, BAK)

with open(ALERT, 'r', encoding='utf-8') as f:
    data = f.read()

# Try normal load first
try:
    objs = json.loads(data)
    print('JSON already valid. No repair needed. Items:', len(objs))
    sys.exit(0)
except Exception as e:
    print('Initial json.loads failed:', e)

# Attempt to extract JSON objects inside top-level array using raw_decode
dec = JSONDecoder()
s = data.strip()
# Find first '['
start = s.find('[')
if start == -1:
    print('No leading array bracket found; aborting')
    sys.exit(2)
idx = start + 1
objs = []
length = len(s)
while True:
    # skip whitespace and commas
    while idx < length and s[idx] in ' \n\t\r,':
        idx += 1
    if idx >= length:
        break
    if s[idx] == ']':
        break
    try:
        obj, j = dec.raw_decode(s, idx)
        objs.append(obj)
        idx = j
    except Exception as ex:
        print('Decoding failed at index', idx, 'error:', ex)
        # try to find the next '}' and continue
        next_brace = s.find('}', idx)
        if next_brace == -1:
            break
        idx = next_brace + 1

print('Recovered', len(objs), 'objects')
if not objs:
    print('No objects recovered; aborting')
    sys.exit(3)

# Write repaired file
with open(REPAIRED, 'w', encoding='utf-8') as f:
    json.dump(objs, f, indent=4)

# Replace original with repaired file
shutil.copy2(REPAIRED, ALERT)
print('Wrote repaired file to', REPAIRED, 'and replaced original')
print('Backup is at', BAK)
print('Done')
