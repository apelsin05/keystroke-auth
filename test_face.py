import base64
from utils.database import init_db
from utils import agent_face

import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

init_db()

test_user_id = "a1b2e510-ab70-4421-b692-4de11dd1a1ef"

with open("facial-expressions1.png", "rb") as f:
    frame_enroll = base64.b64encode(f.read()).decode()

with open("face-impostor.png", "rb") as f:
    frame_verify = base64.b64encode(f.read()).decode()

# Enroll cu poza1
result = agent_face.enroll(test_user_id, [frame_enroll, frame_enroll, frame_enroll])
print("Enroll:", result)

# Verify cu poza2 (diferita)
result = agent_face.analyze(test_user_id, frame_verify, login_id="login-2")
print("Analyze:", result)
print("Distanta:", result['distance'])