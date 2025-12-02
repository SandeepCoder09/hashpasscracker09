/* Hash Pass Decoder - Hacker Edition */

const $ = (s) => document.querySelector(s);

const logEl = $('#log');
const inputEl = $('#input');
const resultEl = $('#result');
const detectedEl = $('#detected');
const algoUsedEl = $('#algoUsed');
const prog = $('#prog');
const progText = $('#progText');
const algoSelect = $('#algoSelect');

const detectBtn = $('#detectBtn');
const identifyBtn = $('#identifyBtn');
const genHashBtn = $('#genHashBtn');
const base64Btn = $('#base64Btn');
const crackBtn = $('#crackBtn');
const wordlistPreview = $('#wordlistPreview');
const wordlistFile = $('#wordlistFile');
const copyBtn = $('#copyBtn');
const downloadBtn = $('#downloadBtn');
const clearBtn = $('#clearBtn');

function log(...msg) {
  logEl.textContent += "\n> " + msg.join(" ");
  logEl.scrollTop = logEl.scrollHeight;
}

// HASH TYPE DETECTION
function detectHashType(hash) {
  const s = hash.trim();
  if (!s) return 'empty';
  if (/^[A-Za-z0-9+/=]+$/.test(s) && s.length % 4 === 0) return 'base64';
  if (/^[a-f0-9]{32}$/i.test(s)) return 'md5';
  if (/^[a-f0-9]{40}$/i.test(s)) return 'sha1';
  if (/^[a-f0-9]{64}$/i.test(s)) return 'sha256';
  if (/^[a-f0-9]{128}$/i.test(s)) return 'sha512';
  if (/\$2[aby]\$\d{2}\$.+/.test(s)) return 'bcrypt';
  return 'unknown';
}

// HASH GENERATOR
async function generateHash(text, algo) {
  algo = algo.toLowerCase();

  if (algo === "md5") return SparkMD5.hash(text);
  if (algo === "bcrypt") return bcrypt.hashSync(text, bcrypt.genSaltSync(10));

  const enc = new TextEncoder();
  const data = enc.encode(text);
  const digest = await crypto.subtle.digest(algo.toUpperCase(), data);

  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// BASE64
function base64Encode(str) {
  try { return btoa(unescape(encodeURIComponent(str))); }
  catch { return "INVALID INPUT"; }
}
function base64Decode(str) {
  try { return decodeURIComponent(escape(atob(str))); }
  catch { return "INVALID BASE64"; }
}

// BUTTON LOGIC
detectBtn.onclick = () => {
  const type = detectHashType(inputEl.value);
  detectedEl.textContent = "Detected: " + type;
  log("Detected:", type);
};

identifyBtn.onclick = () => {
  const v = inputEl.value.trim();
  const type = algoSelect.value === "auto" ? detectHashType(v) : algoSelect.value;

  detectedEl.textContent = "Detected: " + type;
  algoUsedEl.textContent = "Algo: " + type;

  if (type === "base64") {
    resultEl.textContent = base64Decode(v);
    log("Base64 decoded.");
    return;
  }

  resultEl.textContent = "This looks like a " + type + " hash.";
};

genHashBtn.onclick = async () => {
  const text = inputEl.value;
  if (!text) return alert("ENTER TEXT FIRST.");

  const algo = algoSelect.value === "auto" ? "sha256" : algoSelect.value;
  log("Generating hash:", algo);

  const h = await generateHash(text, algo);
  resultEl.textContent = h;

  algoUsedEl.textContent = "Algo: " + algo;
};

base64Btn.onclick = () => {
  const v = inputEl.value.trim();
  if (!v) return alert("ENTER TEXT.");

  if (detectHashType(v) === "base64") {
    resultEl.textContent = base64Decode(v);
    algoUsedEl.textContent = "Base64 (decoded)";
  } else {
    resultEl.textContent = base64Encode(v);
    algoUsedEl.textContent = "Base64 (encoded)";
  }
};

// WORDLIST FILE READER
wordlistFile.onchange = (e) => {
  const f = e.target.files[0];
  if (!f) return;
  const reader = new FileReader();
  reader.onload = () => {
    wordlistPreview.value = reader.result;
    log("Wordlist loaded.");
  };
  reader.readAsText(f);
};

// COPY
copyBtn.onclick = async () => {
  await navigator.clipboard.writeText(resultEl.textContent);
  log("Copied result.");
};

// DOWNLOAD
downloadBtn.onclick = () => {
  const blob = new Blob([resultEl.textContent], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "result.txt";
  a.click();
  log("Downloaded result.");
};

// CLEAR
clearBtn.onclick = () => {
  inputEl.value = "";
  resultEl.textContent = "—";
  wordlistPreview.value = "";
  detectedEl.textContent = "Detected: —";
  algoUsedEl.textContent = "Algo: —";
  prog.value = 0;
  progText.textContent = "";
  log("Cleared.");
};

// CRACK HASH
crackBtn.onclick = async () => {
  const target = inputEl.value.trim();
  if (!target) return alert("ENTER A HASH.");

  const algo = detectHashType(target);
  let words = wordlistPreview.value.split(/\r?\n/).filter(Boolean);

  prog.max = words.length;
  log("Cracking with", words.length, "words...");

  for (let i = 0; i < words.length; i++) {
    let w = words[i];
    prog.value = i + 1;
    progText.textContent = `${i+1}/${words.length}`;

    let h = await generateHash(w, algo);
    if (h.toLowerCase() === target.toLowerCase()) {
      resultEl.textContent = "FOUND: " + w;
      log("MATCH FOUND:", w);
      return;
    }
  }

  resultEl.textContent = "Not found.";
  log("DONE. No match.");
};

// init
log("READY.");
