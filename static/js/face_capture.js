// ── Bloc 1 — Configurație și stare globală ─────────────────────────────────
const videoElement  = document.getElementById('face-video');
const canvasElement = document.getElementById('face-canvas');
const ctx           = canvasElement.getContext('2d');
const statusMsg     = document.getElementById('face-status');

let frames       = [];
let alignedSince = null;
let capturing    = false;
let cameraStream = null; 

const ALIGN_TIMEOUT    = 3000;
const CAPTURE_INTERVAL = 1000;

// Proporțiile box-ului ghid fix, relative la dimensiunile canvas-ului
const GUIDE = { x: 0.20, y: 0.20, w: 0.60, h: 0.60 };

// Toleranță de aliniere față-box (fracție din înălțimea canvas-ului)
const TOLERANCE = 0.15;

// ── Bloc 2 — startCamera() ────────────────────────────────────────────────
async function startCamera() {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ video: true });
    cameraStream = stream; 
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

// ── Bloc 4 — drawGuideBox() ───────────────────────────────────────────────
function drawGuideBox(color) {
  const w = canvasElement.width;
  const h = canvasElement.height;
  ctx.strokeStyle = color;
  ctx.lineWidth   = 3;
  ctx.strokeRect(w * GUIDE.x, h * GUIDE.y, w * GUIDE.w, h * GUIDE.h);
}

// ── Bloc 5 — drawVideoFrame() — implementare manuală a object-fit: cover ──
function drawVideoFrame() {
  const vW = videoElement.videoWidth;
  const vH = videoElement.videoHeight;
  const cW = canvasElement.width;
  const cH = canvasElement.height;

  const scale = Math.max(cW / vW, cH / vH);
  const srcW  = cW / scale;
  const srcH  = cH / scale;
  const srcX  = (vW - srcW) / 2;
  const srcY  = (vH - srcH) / 2;

  ctx.drawImage(videoElement, srcX, srcY, srcW, srcH, 0, 0, cW, cH);
}

// ── Bloc 6 — onResults() + logica de aliniere ─────────────────────────────
function onResults(results) {
  const w = canvasElement.width;
  const h = canvasElement.height;

  ctx.clearRect(0, 0, w, h);

  if (!results.detections || results.detections.length === 0) {
    alignedSince = null;
    drawGuideBox('red');
    statusMsg.textContent = 'Poziționează fața în chenar';
    statusMsg.style.color = '';
    return;
  }

  const box = results.detections[0].boundingBox;

  // Coordonate față în pixeli pe canvas
  const faceTop     = (box.yCenter - box.height / 2) * h;
  const faceBottom  = (box.yCenter + box.height / 2) * h;
  const faceCenterX = box.xCenter * w;
  
  // debug 
  console.log({
  faceTop:     faceTop.toFixed(1),
  faceBottom:  faceBottom.toFixed(1),
  guideTop:    (h * GUIDE.y).toFixed(1),
  guideBottom: (h * (GUIDE.y + GUIDE.h)).toFixed(1),
  tol:         (h * TOLERANCE).toFixed(1),
  diffTop:     Math.abs(faceTop    - h * GUIDE.y).toFixed(1),
  diffBottom:  Math.abs(faceBottom - h * (GUIDE.y + GUIDE.h)).toFixed(1),
});

  // Coordonate box ghid în pixeli
  const guideTop     = h * GUIDE.y;
  const guideBottom  = h * (GUIDE.y + GUIDE.h);
  const guideCenterX = w * (GUIDE.x + GUIDE.w / 2);

  const tol = h * TOLERANCE;

  const aligned =
    Math.abs(faceTop    - guideTop)      < tol &&
    Math.abs(faceBottom - guideBottom)   < tol &&
    Math.abs(faceCenterX - guideCenterX) < w * 0.15;

  if (aligned && !capturing) {
    drawGuideBox('lime');

    if (alignedSince === null) alignedSince = Date.now();
    const elapsed = Date.now() - alignedSince;

    if (elapsed >= ALIGN_TIMEOUT) {
      captureFrames();
    } else {
      const remaining = Math.ceil((ALIGN_TIMEOUT - elapsed) / 1000);
      statusMsg.textContent = `Stai nemișcat: ${remaining}s`;
    }
  } else {
    alignedSince = null;
    drawGuideBox('red');

    const faceHeight = faceBottom - faceTop;
    if (faceHeight < h * GUIDE.h * 0.5) {
      statusMsg.textContent = 'Apropie-te de cameră';
    } else if (faceHeight > h * GUIDE.h * 1.3) {
      statusMsg.textContent = 'Îndepărtează-te puțin';
    } else if (faceTop > guideTop + tol) {
      statusMsg.textContent = 'Ridică privirea';
    } else if (faceBottom < guideBottom - tol) {
      statusMsg.textContent = 'Coboară puțin';
    } else {
      statusMsg.textContent = 'Centrează fața în chenar';
    }
    statusMsg.style.color = '';
  }
}

// ── Bloc 7 — captureFrames() și sendFrames() ──────────────────────────────
function captureFrames() {
  capturing = true;
  frames    = [];

  statusMsg.textContent = 'Capturez... (1/3)';
  drawVideoFrame();
  frames.push(canvasElement.toDataURL('image/jpeg', 0.85));

  setTimeout(() => {
    statusMsg.textContent = 'Capturez... (2/3)';
    drawVideoFrame();
    frames.push(canvasElement.toDataURL('image/jpeg', 0.85));

    setTimeout(() => {
      statusMsg.textContent = 'Capturez... (3/3)';
      drawVideoFrame();
      frames.push(canvasElement.toDataURL('image/jpeg', 0.85));
      showConfirmation();
    }, CAPTURE_INTERVAL);
  }, CAPTURE_INTERVAL);
}

async function sendFrames() {
  try {
    const res = await fetch('/register/face', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ frames })
    });

    if (res.ok) {
      statusMsg.textContent = 'Față înregistrată cu succes!';
      statusMsg.style.color = 'green';
      stopCamera();
      if (typeof window.onFaceEnrollSuccess === 'function') window.onFaceEnrollSuccess();
    } else {
      const data = await res.json();
      statusMsg.textContent = data.message || 'Eroare la înregistrarea feței.';
      statusMsg.style.color = 'red';
      frames = []; alignedSince = null; capturing = false;
    }
  } catch (err) {
    statusMsg.textContent = 'Eroare de rețea: ' + err.message;
    statusMsg.style.color = 'red';
    frames = []; alignedSince = null; capturing = false;
  }
}

// ── Bloc 8 — Confirmare cadre capturate ───────────────────────────────────
function showConfirmation() {
  document.getElementById('face-thumb-1').src = frames[0];
  document.getElementById('face-thumb-2').src = frames[1];
  document.getElementById('face-thumb-3').src = frames[2];
  document.getElementById('face-confirm-section').style.display = '';
  canvasElement.parentElement.style.display = 'none';
  statusMsg.textContent = 'Verifica imaginile capturate.';
  statusMsg.style.color = '';
}

function resetCapture() {
  frames       = [];
  alignedSince = null;
  capturing    = false;
  document.getElementById('face-confirm-section').style.display = 'none';
  canvasElement.parentElement.style.display = '';
  statusMsg.textContent = 'Pozitioneaza fata in chenar';
  statusMsg.style.color = '';
}

function stopCamera() {
  if (cameraStream) {
    cameraStream.getTracks().forEach(t => t.stop());
    cameraStream = null;
  }
}

// ── Wiring butoane confirmare ──────────────────────────────────────────────
document.getElementById('face-confirm-yes').addEventListener('click', sendFrames);
document.getElementById('face-confirm-no').addEventListener('click', resetCapture);
