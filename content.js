// Cache global para evaluaciones por messageKey
const evaluationCache = {};
let currentMessageKey = null;

function safeText(el) {
  if (!el) return "";
  return (el.innerText || el.textContent || "").trim();
}

function limit(str, n) {
  const s = (str || "").trim();
  return s.length > n ? s.slice(0, n) : s;
}

function getProvider() {
  const host = location.host;
  if (host === "mail.google.com") return "gmail";
  if (host === "outlook.live.com" || host === "outlook.office.com") return "outlook";
  return "unknown";
}

function getMessageKey(emailData) {
  if (!emailData) return null;
  // Clave única: sender + subject (identificador de correo único)
  return `${emailData.senderAddress}:::${emailData.subject}`;
}

function extractGmail() {
  const senderEl = document.querySelector("span[email]");
  const senderAddress = senderEl?.getAttribute("email") || "";

  const subjectEl =
    document.querySelector("h2") ||
    document.querySelector('div[role="main"] h2') ||
    document.querySelector('div[role="main"] div[role="heading"]');
  const subject = safeText(subjectEl);

  const main = document.querySelector('div[role="main"]');
  if (!main) return null;

  const bodyText = safeText(main);

  const links = Array.from(main.querySelectorAll("a"))
    .map((a) => ({ href: a.href, text: (a.innerText || "").trim() }))
    .filter((l) => l.href && /^https?:\/\//i.test(l.href));

  const bodyExcerpt = limit(bodyText, 2000);
  if (!subject && bodyExcerpt.length < 30 && links.length === 0 && !senderAddress) return null;

  return {
    provider: "gmail",
    senderAddress,
    subject: limit(subject, 300),
    bodyExcerpt,
    links
  };
}

function extractOutlook() {
  const main =
    document.querySelector('div[role="main"]') ||
    document.querySelector('div[aria-label*="Reading pane" i]') ||
    document.querySelector('div[aria-label*="Panel de lectura" i]');
  if (!main) return null;

  const mailto = main.querySelector('a[href^="mailto:"]');
  const senderAddress = mailto
    ? (mailto.getAttribute("href") || "").replace(/^mailto:/i, "").split("?")[0]
    : "";

  const subjectEl =
    main.querySelector('h1, h2, div[role="heading"]') ||
    document.querySelector('h1, h2, div[role="heading"]');
  const subject = safeText(subjectEl);

  const bodyText = safeText(main);

  const links = Array.from(main.querySelectorAll("a"))
    .map((a) => ({ href: a.href, text: (a.innerText || "").trim() }))
    .filter((l) => l.href && /^https?:\/\//i.test(l.href));

  const bodyExcerpt = limit(bodyText, 2000);
  if (!subject && bodyExcerpt.length < 30 && links.length === 0 && !senderAddress) return null;

  return {
    provider: "outlook",
    senderAddress,
    subject: limit(subject, 300),
    bodyExcerpt,
    links
  };
}

function extractEmailData() {
  const provider = getProvider();
  if (provider === "gmail") return extractGmail();
  if (provider === "outlook") return extractOutlook();
  return null;
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg) return;

  if (msg.type === "MAILSAFE_PING") {
    sendResponse({ ok: true });
    return;
  }

  if (msg.type !== "MAILSAFE_EXTRACT") return;

  try {
    const data = extractEmailData();
    if (!data) {
      sendResponse({ ok: false, error: "No detecté un correo abierto. Abre el correo y vuelve a intentar." });
      return;
    }

    data.bodyExcerpt = (data.bodyExcerpt || "").slice(0, 2000);
    if (Array.isArray(data.links)) data.links = data.links.slice(0, 50);

    // Generar messageKey y verificar si hay caché
    const messageKey = getMessageKey(data);
    const hasCache = messageKey && evaluationCache[messageKey];

    sendResponse({ 
      ok: true, 
      data,
      messageKey,
      hasCache
    });
  } catch (e) {
    sendResponse({ ok: false, error: e?.message || String(e) });
  }
  return true;
});

// Watcher para detectar cambios de correo en Gmail (SPA)
function initEmailWatcher() {
  const provider = getProvider();
  
  if (provider === "gmail") {
    const observer = new MutationObserver(() => {
      const currentData = extractEmailData();
      const newMessageKey = getMessageKey(currentData);
      
      // Si el correo cambió, notificar al popup
      if (newMessageKey !== currentMessageKey) {
        currentMessageKey = newMessageKey;
        
        // Notificar al popup que cambió el correo
        chrome.runtime.sendMessage({
          type: "MAILSAFE_EMAIL_CHANGED",
          messageKey: newMessageKey,
          data: currentData
        }).catch(() => {
          // El popup no está abierto, ignorar error
        });
      }
    });

    const container = document.querySelector('div[role="main"]') || document.body;
    observer.observe(container, {
      childList: true,
      subtree: true,
      characterData: false,
      attributes: true,
      attributeFilter: ["email", "aria-label"]
    });
  }
}

// Inicializar watcher cuando se carga el content script
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initEmailWatcher);
} else {
  initEmailWatcher();
}
