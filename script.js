/* Hash Pass Decoder - Hacker Edition (Clean Fixed Version) */

const $ = (s) => document.querySelector(s);

/* Elements */
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

/* Logger */
function log(...msg) {
  logEl.textContent += `\n> ${msg.join(" ")}`;
  logEl.scrollTop = logEl.scrollHeight;
}

/* Detect hash type */
function detectHashType(hash) {
  const s = hash.trim();
  if (!s) return "empty";

  if (/^[A-Za-z0-9+/=]+$/.test(s) && s.length % 4 === 0) return "base64";
  if (/^[a-f0-9]{32}$/i.test(s)) return "md5";
  if (/^[a-f0-9]{40}$/i.test(s)) return "sha1";
  if (/^[a-f0-9]{64}$/i.test(s)) return "sha256";
  if (/^[a-f0-9]{128}$/i.test(s)) return "sha512";
  if (/\$2[aby]\$\d{2}\$.+/.test(s)) return "bcrypt";

  return "unknown";
}

/* Generate hash (MD5 / SHA / bcrypt) */
async function generateHash(text, algo) {
  algo = algo.toLowerCase();

  if (algo === "md5") return SparkMD5.hash(text);
  if (algo === "bcrypt") return bcrypt.hashSync(text, bcrypt.genSaltSync(10));

  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest(algo.toUpperCase(), data);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

/* Base64 */
function base64Encode(str) {
  try { return btoa(unescape(encodeURIComponent(str))); }
  catch { return "INVALID INPUT"; }
}

function base64Decode(str) {
  try { return decodeURIComponent(escape(atob(str))); }
  catch { return "INVALID BASE64"; }
}

/* Buttons ========================== */

detectBtn.onclick = () => {
  const t = detectHashType(inputEl.value);
  detectedEl.textContent = "Detected: " + t;
  algoUsedEl.textContent = "Algo: " + t;
  log("Detected:", t);
};

identifyBtn.onclick = () => {
  const v = inputEl.value.trim();
  const type = algoSelect.value === "auto" ? detectHashType(v) : algoSelect.value;

  detectedEl.textContent = "Detected: " + type;
  algoUsedEl.textContent = "Algo: " + type;

  if (type === "base64") {
    resultEl.textContent = base64Decode(v);
    log("Decoded Base64.");
    return;
  }

  if (type === "unknown") {
    resultEl.textContent = "Unknown hash type.";
    return;
  }

  resultEl.textContent = `This looks like a ${type} hash.`;
};

/* Generate hash */
genHashBtn.onclick = async () => {
  const text = inputEl.value;
  if (!text) return alert("Enter text to hash!");

  const algo = algoSelect.value === "auto" ? "sha256" : algoSelect.value;
  log("Generating hash:", algo);

  const hash = await generateHash(text, algo);
  resultEl.textContent = hash;
  algoUsedEl.textContent = "Algo: " + algo;
};

/* Base64 */
base64Btn.onclick = () => {
  const v = inputEl.value.trim();
  if (!v) return alert("Enter text!");

  if (detectHashType(v) === "base64") {
    resultEl.textContent = base64Decode(v);
    algoUsedEl.textContent = "Base64 (decoded)";
  } else {
    resultEl.textContent = base64Encode(v);
    algoUsedEl.textContent = "Base64 (encoded)";
  }
};

/* Load wordlist */
wordlistFile.onchange = (e) => {
  const file = e.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = () => {
    wordlistPreview.value = reader.result;
    log("Wordlist loaded:", file.name);
  };
  reader.readAsText(file);
};

/* COPY */
copyBtn.onclick = async () => {
  await navigator.clipboard.writeText(resultEl.textContent);
  log("Copied result.");
};

/* DOWNLOAD */
downloadBtn.onclick = () => {
  const blob = new Blob([resultEl.textContent], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "result.txt";
  a.click();
  log("Downloaded result.");
};

/* CLEAR */
clearBtn.onclick = () => {
  inputEl.value = "";
  resultEl.textContent = "—";
  detectedEl.textContent = "Detected: —";
  algoUsedEl.textContent = "Algo: —";
  wordlistPreview.value = "";
  prog.value = 0;
  progText.textContent = "";
  log("Cleared.");
};

/* HASH CRACKER (Fully Fixed Version) */
crackBtn.onclick = async () => {
  const target = inputEl.value.trim();
  if (!target) return alert("Enter hash to crack!");

  const detected = algoSelect.value === "auto" ? detectHashType(target) : algoSelect.value;

  detectedEl.textContent = "Detected: " + detected;
  algoUsedEl.textContent = "Algo: " + detected;

  let words = wordlistPreview.value.split(/\r?\n/).filter(Boolean);
  if (words.length === 0) return alert("Paste or upload a wordlist!");

  log("Cracking", detected, "with", words.length, "words...");

  prog.max = words.length;
  prog.value = 0;

  /* BCRYPT (Real working crack) */
  if (detected === "bcrypt") {
    for (let i = 0; i < words.length; i++) {
      const word = words[i];

      prog.value = i + 1;
      progText.textContent = `${i + 1}/${words.length}`;
      await new Promise(r => setTimeout(r));

      if (bcrypt.compareSync(word, target)) {
        resultEl.textContent = "FOUND: " + word;
        log("MATCH FOUND (bcrypt):", word);
        return;
      }
    }

    resultEl.textContent = "No match found.";
    log("Done. No bcrypt match.");
    return;
  }

  /* Other hashes (md5, sha1, sha256, sha512) */
  for (let i = 0; i < words.length; i++) {
    const word = words[i];

    prog.value = i + 1;
    progText.textContent = `${i + 1}/${words.length}`;
    await new Promise(r => setTimeout(r));

    const hashed = await generateHash(word, detected);
    if (hashed.toLowerCase() === target.toLowerCase()) {
      resultEl.textContent = "FOUND: " + word;
      log("MATCH FOUND:", word);
      return;
    }
  }

  resultEl.textContent = "No match found.";
  log("DONE. No match.");
};

/* Init */
log("READY.");
