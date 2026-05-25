// ── Bloc 1 — Configurație și stare globală ────────────────────────────────
const videoElement  = document.getElementById('face-video');
const canvasElement = document.getElementById('face-canvas');
const ctx           = canvasElement.getContext('2d');
const statusMsg     = document.getElementById('face-status');

let frames       = [];
let alignedSince = null;
let capturing    = false;

const ALIGN_TIMEOUT    = 3000;
const CAPTURE_INTERVAL = 1000;

// ── Bloc 2 — startCamera() ────────────────────────────────────────────────
async function startCamera() {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ video: true });
    videoElement.srcObject = stream;
    videoElement.onloadedmetadata = () => {
        canvasElement.width  = videoElement.clientWidth;
        canvasElement.height = videoElement.clientHeight;
      setupMediaPipe();
    };
  } catch (err) {
    statusMsg.textContent = 'Eroare la accesarea camerei: ' + err.message;
    statusMsg.style.color = 'red';
  }
}

// ── Bloc 3 — setupMediaPipe() ─────────────────────────────────────────────
function setupMediaPipe() {
  const faceDetection = new FaceDetection({
    locateFile: (file) =>
      `https://cdn.jsdelivr.net/npm/@mediapipe/face_detection/${file}`
  });

  faceDetection.setOptions({ minDetectionConfidence: 0.7, model: 'short' });
  faceDetection.onResults(onResults);

  async function loop() {
    await faceDetection.send({ image: videoElement });
    requestAnimationFrame(loop);
  }
  requestAnimationFrame(loop);
}

// ── Bloc 4 — onResults() + logica de aliniere ─────────────────────────────
function onResults(results) {
    
    ctx.clearRect(0, 0, canvasElement.width, canvasElement.height);
    const w = canvasElement.width;
    const h = canvasElement.height;

  if (!results.detections || results.detections.length === 0) {
    alignedSince = null;
    ctx.strokeStyle = 'red';
    ctx.lineWidth   = 3;
    ctx.strokeRect(w * 0.2, h * 0.1, w * 0.6, h * 0.8);
    statusMsg.textContent = 'Poziționează fața în centru';
    statusMsg.style.color = '';
    return;
  }

  const box = results.detections[0].boundingBox;
  const { xCenter, yCenter } = box;
  const centered = xCenter >= 0.35 && xCenter <= 0.65 &&
                   yCenter >= 0.25 && yCenter <= 0.75;

  const rx = (xCenter - box.width  / 2) * w;
  const ry = (yCenter - box.height / 2) * h;

  if (centered) {
    ctx.strokeStyle = 'lime';
    ctx.lineWidth   = 3;
    ctx.strokeRect(rx, ry, box.width * w, box.height * h);

    if (!capturing) {
      if (alignedSince === null) {
        alignedSince = Date.now();
      }
      const elapsed = Date.now() - alignedSince;
      if (elapsed >= ALIGN_TIMEOUT) {
        captureFrames();
      } else {
        const remaining = Math.ceil((ALIGN_TIMEOUT - elapsed) / 1000);
        statusMsg.textContent = `Stai nemișcat: ${remaining}s`;
        statusMsg.style.color = '';
      }
    }
  } else {
    alignedSince = null;
    ctx.strokeStyle = 'red';
    ctx.lineWidth   = 3;
    ctx.strokeRect(rx, ry, box.width * w, box.height * h);
    statusMsg.textContent = 'Poziționează fața în centru';
    statusMsg.style.color = '';
  }
}

// ── Bloc 5 — captureFrames() și sendFrames() ──────────────────────────────
function captureFrames() {
  capturing = true;
  frames    = [];

  statusMsg.textContent = 'Capturez... (1/3)';
  ctx.drawImage(videoElement, 0, 0);
  frames.push(canvasElement.toDataURL('image/jpeg', 0.85));

  setTimeout(() => {
    statusMsg.textContent = 'Capturez... (2/3)';
    ctx.drawImage(videoElement, 0, 0);
    frames.push(canvasElement.toDataURL('image/jpeg', 0.85));

    setTimeout(() => {
      statusMsg.textContent = 'Capturez... (3/3)';
      ctx.drawImage(videoElement, 0, 0);
      frames.push(canvasElement.toDataURL('image/jpeg', 0.85));
      sendFrames();
    }, CAPTURE_INTERVAL);
  }, CAPTURE_INTERVAL);
}

async function sendFrames() {
  try {
    const res = await fetch('/register/face', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ frames })
    });

    if (res.ok) {
      statusMsg.textContent = '✓ Față înregistrată cu succes!';
      statusMsg.style.color = 'green';
    } else {
      const data = await res.json();
      statusMsg.textContent = data.error || 'Eroare la înregistrarea feței.';
      statusMsg.style.color = 'red';
      frames       = [];
      alignedSince = null;
      capturing    = false;
    }
  } catch (err) {
    statusMsg.textContent = 'Eroare de rețea: ' + err.message;
    statusMsg.style.color = 'red';
    frames       = [];
    alignedSince = null;
    capturing    = false;
  }
}

// ── Start ─────────────────────────────────────────────────────────────────
startCamera();
