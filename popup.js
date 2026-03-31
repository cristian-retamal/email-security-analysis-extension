const $ = (id) => document.getElementById(id);
const analysisApi = window.MailSafeAnalysis;
const analyzeLocally = analysisApi?.analyzeLocally;
const parseEmlBasic = analysisApi?.parseEmlBasic;

// Cache para evaluaciones por sourceKey (messageKey, archivo, etc.)
const analysisCache = new Map();
let currentMessageKey = null;

const analyzeBtn = $("analyzeBtn");
const status = $("status");
const statusText = $("statusText");
const hint = $("hint");
const errorBox = $("error");

const verdictPill = $("verdictPill");
const reason1 = $("reason1");
const reason2 = $("reason2");

const providerEl = $("provider");
const senderDomainEl = $("senderDomain");
const linkDomainsEl = $("linkDomains");
const findingsListEl = $("findingsList");

const emlFile = document.getElementById("emlFile");

if (!analyzeLocally || !parseEmlBasic) {
  console.error("MailSafeAnalysis no está disponible en window.", { analysisApi });
  if (errorBox) {
    errorBox.textContent = "No se pudo cargar el motor de análisis. Recarga la extensión e intenta de nuevo.";
    errorBox.classList.remove("hidden");
  }
}

if (emlFile) {
  emlFile.addEventListener("change", () => {
    const file = emlFile.files?.[0];
    if (!file) return;

    if (!parseEmlBasic) {
      showError("El motor de análisis no está disponible.");
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const raw = String(reader.result || "");
      const email = parseEmlBasic(raw);
      const fileKey = `eml:${file.name}:${file.size}:${file.lastModified}`;
      renderAnalysis(email, analyzeEmailData(fileKey, email));
    };
    reader.readAsText(file);
  });
}

function showError(msg) {
  errorBox.textContent = msg;
  errorBox.classList.remove("hidden");
}

function clearError() {
  errorBox.textContent = "";
  errorBox.classList.add("hidden");
}

function setPill(level, label) {
  verdictPill.className = "pill " + level;
  verdictPill.textContent = label;
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function requestExtractionFromPage(tabId) {
  return await chrome.tabs.sendMessage(tabId, { type: "MAILSAFE_EXTRACT" });
}

async function ensureContentScript(tabId) {
  try {
    const ping = await chrome.tabs.sendMessage(tabId, { type: "MAILSAFE_PING" });
    if (ping?.ok) return;
  } catch {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ["content.js"]
    });
  }
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg && msg.type === "MAILSAFE_EMAIL_CHANGED") {
    const newMessageKey = msg.messageKey;

    if (newMessageKey !== currentMessageKey) {
      currentMessageKey = newMessageKey;
      resetEvaluation();
    }
  }
});

function resetEvaluation() {
  hint.classList.remove("hidden");
  status.classList.add("hidden");
  if (statusText) statusText.textContent = "";
  verdictPill.className = "pill";
  verdictPill.textContent = "";
  reason1.textContent = "";
  reason2.textContent = "";
  providerEl.textContent = "—";
  senderDomainEl.textContent = "—";
  linkDomainsEl.textContent = "—";
  if (findingsListEl) findingsListEl.innerHTML = "";
  clearError();
}

function prepareForAnalysis() {
  hint.classList.add("hidden");
  status.classList.remove("hidden");
  if (statusText) statusText.textContent = "Analizando correo...";
  analyzeBtn.disabled = false;
}

function renderAnalysis(email, result) {
  const label =
    result.level === "red" ? "🔴 Riesgo alto" :
    result.level === "yellow" ? "🟡 Precaución" :
    "🟢 Se ve normal";

  if (statusText) statusText.textContent = `Nivel de análisis: ${label}`;
  setPill(result.level, label);

  reason1.textContent = result.reasons[0] || "";
  reason2.textContent = result.reasons[1] || "";

  providerEl.textContent = email.provider || "—";
  senderDomainEl.textContent = result.senderDomain || "—";
  linkDomainsEl.textContent = (result.linkDomains && result.linkDomains.length)
    ? result.linkDomains.join(", ")
    : "—";

  if (findingsListEl) {
    findingsListEl.innerHTML = "";
    const findings = Array.isArray(result.findings) ? result.findings : [];
    for (const finding of findings) {
      const item = document.createElement("li");
      item.textContent = finding;
      findingsListEl.appendChild(item);
    }
  }
}

function analyzeEmailData(sourceKey, emailData) {
  if (!analyzeLocally) {
    throw new Error("El motor de análisis no está disponible.");
  }

  if (sourceKey && analysisCache.has(sourceKey)) {
    return analysisCache.get(sourceKey);
  }

  const result = analyzeLocally(emailData);
  if (sourceKey) {
    analysisCache.set(sourceKey, result);
  }
  return result;
}

analyzeBtn.addEventListener("click", async () => {
  clearError();
  analyzeBtn.disabled = true;
  analyzeBtn.textContent = "Analizando...";
  prepareForAnalysis();

  try {
    const tab = await getActiveTab();
    if (!tab || !tab.id || !tab.url) {
      throw new Error("No se pudo acceder a la pestaña activa.");
    }

    const isAllowed =
      tab.url.startsWith("https://mail.google.com/") ||
      tab.url.startsWith("https://outlook.live.com/") ||
      tab.url.startsWith("https://outlook.office.com/");

    if (!isAllowed) {
      throw new Error("Abre un correo en Gmail u Outlook Web para analizar.");
    }

    await ensureContentScript(tab.id);
    const email = await requestExtractionFromPage(tab.id);
    if (!email || !email.ok) {
      throw new Error(email?.error || "No pude extraer el correo. Abre un correo (no la lista) e intenta de nuevo.");
    }

    currentMessageKey = email.messageKey;

    const result = analyzeEmailData(email.messageKey, email.data);
    renderAnalysis(email.data, result);
  } catch (e) {
    showError(e?.message || String(e));
    if (statusText) statusText.textContent = "";
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = "Analizar este correo";
  }
});
