# test_keystroke.py — rulat cu: python test_keystroke.py
import sys
sys.path.insert(0, '.')
from utils.agent_keystroke import (
    load_enrollment_samples, train_manhattan_profile,
    calibrate_threshold, score_manhattan_scaled,
    _raw_to_keystroke_score, compare_profiles
)

CSV   = 'data/keystrokes.csv'
USER  = 'a1b2e510-ab70-4421-b692-4de11dd1a1ef'   # testapr@g.com — 24 probe
DEV   = '177efd56-c0d7-4ac1-a01b-dded0ae7c89a'

samples = load_enrollment_samples(CSV, USER, DEV)
print(f'Probe enrollment: {len(samples)}')

profile   = train_manhattan_profile(samples)
threshold = calibrate_threshold(samples)
print(f'Threshold calibrat: {threshold:.3f}')

# Scorăm fiecare probă din enrollment față de restul (LOO)
print('\nScoruri leave-one-out (toate ar trebui să fie ALLOW):')
for i, s in enumerate(samples):
    rest = [f for j, f in enumerate(samples) if j != i]
    if len(rest) >= 3:
        p   = train_manhattan_profile(rest)
        raw = score_manhattan_scaled(p, s)
        ks  = _raw_to_keystroke_score(raw, threshold)
        tag = 'ALLOW' if ks >= 0.3 else ('2FA' if ks >= 0.1 else 'REENROLL')
        print(f'  Sample {i+1:2d}: raw={raw:.2f} → score={ks:.3f} [{tag}]')