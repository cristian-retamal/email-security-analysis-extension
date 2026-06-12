window.MailSafeI18n = (() => {
  const messages = {
    en: {
      subtitle: "On-demand Analysis",
      analyzeBtn: "Analyze this email",
      uploadLabel: "or analyze .eml file",
      detailsSummary: "View diagnostic details",
      signalsTitle: "Detected signals",
      providerLabel: "Provider:",
      senderDomainLabel: "Sender domain:",
      linkDomainsLabel: "Link domains:",
      hint: 'Open an email in Gmail or Outlook Web and press "Analyze".',
      loadError: "Could not load the analysis engine. Reload the extension and try again.",
      engineUnavailable: "The analysis engine is not available.",
      analyzing: "Analyzing email...",
      analyzingBtn: "Analyzing...",
      verdictHigh: "🔴 High risk",
      verdictCaution: "🟡 Caution",
      verdictNormal: "🟢 Looks normal",
      analysisLevel: "Analysis level: {label}",
      tabError: "Could not access the active tab.",
      domainError: "Open an email in Gmail or Outlook Web to analyze.",
      extractFailed: "Could not extract the email. Open an email (not the list) and try again.",
      noEmailOpen: "No open email detected. Open the email and try again.",
      defaultReason: "No clear risk signals were detected in the visible content.",
      ipLink: "There is a link pointing to an IP address (very suspicious).",
      shortenedLink: "There is a shortened link (may hide the real destination).",
      punycodeLink: "There is a link with a strange domain (possible spoofing).",
      freeHostingLink: "There is a link hosted on a free platform, common in fraudulent campaigns.",
      suspiciousDomain: "One of the links uses an untrustworthy domain shape.",
      redirectorLink: "There is a link that redirects before reaching the final destination.",
      linkTextMismatch: "The link text does not match the actual site (possible spoofing).",
      institutionalMismatch: "The link points to an institutional site different from the displayed text.",
      urgencyWithLinks: "Urgency language alongside links (typical phishing pattern).",
      urgencyAlone: "Urgency language (caution).",
      asksSecrets: "The message asks for passwords/codes or money (high risk).",
      manyLinks: "Contains many links (review before clicking).",
      shortWithLink: "Very short message with a link (common deception pattern).",
      microsoftImpersonation: "The message appears to be from Microsoft, but the sender does not use an official domain.",
      accountVerification: "The email asks to validate or verify the account, a common access theft tactic.",
      freeHostingInContent: "A free or unreliable hosting domain appears in the message content.",
      microsoftExternalLink: "The email impersonates Microsoft but links to an external site.",
      microsoftPhishingPattern: "The combination of a non-Microsoft sender and a verification request indicates a high probability of phishing.",
      brandImpersonation: "The email mentions {brand} but links to an unrelated domain.",
      transactionalNotice: "The message looks like a transactional notice or receipt, not an account access request.",
    },
    es: {
      subtitle: "Análisis a demanda",
      analyzeBtn: "Analizar este correo",
      uploadLabel: "o analizar archivo .eml",
      detailsSummary: "Ver detalle del diagnóstico",
      signalsTitle: "Señales detectadas",
      providerLabel: "Proveedor:",
      senderDomainLabel: "Dominio remitente:",
      linkDomainsLabel: "Dominios links:",
      hint: 'Abre un correo en Gmail o Outlook Web y presiona "Analizar".',
      loadError: "No se pudo cargar el motor de análisis. Recarga la extensión e intenta de nuevo.",
      engineUnavailable: "El motor de análisis no está disponible.",
      analyzing: "Analizando correo...",
      analyzingBtn: "Analizando...",
      verdictHigh: "🔴 Riesgo alto",
      verdictCaution: "🟡 Precaución",
      verdictNormal: "🟢 Se ve normal",
      analysisLevel: "Nivel de análisis: {label}",
      tabError: "No se pudo acceder a la pestaña activa.",
      domainError: "Abre un correo en Gmail u Outlook Web para analizar.",
      extractFailed: "No pude extraer el correo. Abre un correo (no la lista) e intenta de nuevo.",
      noEmailOpen: "No detecté un correo abierto. Abre el correo y vuelve a intentar.",
      defaultReason: "No se detectaron señales claras de riesgo en lo visible.",
      ipLink: "Hay un enlace que apunta a una dirección IP (muy sospechoso).",
      shortenedLink: "Hay un enlace acortado (puede ocultar el destino real).",
      punycodeLink: "Hay un enlace con dominio extraño (posible suplantación).",
      freeHostingLink: "Hay un enlace alojado en una plataforma gratuita, algo común en campañas fraudulentas.",
      suspiciousDomain: "Uno de los enlaces usa un dominio con forma poco confiable.",
      redirectorLink: "Hay un enlace que redirige antes de llegar al destino final.",
      linkTextMismatch: "El texto del enlace no coincide con el sitio real (posible suplantación).",
      institutionalMismatch: "El enlace apunta a un sitio institucional distinto al texto mostrado.",
      urgencyWithLinks: "Lenguaje de urgencia junto a enlaces (patrón típico de phishing).",
      urgencyAlone: "Lenguaje de urgencia (precaución).",
      asksSecrets: "El mensaje sugiere pedir claves/códigos o dinero (alto riesgo).",
      manyLinks: "Contiene muchos enlaces (revisa antes de hacer clic).",
      shortWithLink: "Mensaje muy corto con enlace (patrón común de engaños).",
      microsoftImpersonation: "El mensaje aparenta ser de Microsoft, pero el remitente no usa un dominio oficial.",
      accountVerification: "El correo pide validar o verificar la cuenta, una táctica común de robo de acceso.",
      freeHostingInContent: "Aparece un dominio de hosting gratuito o poco confiable en el contenido del mensaje.",
      microsoftExternalLink: "El correo se hace pasar por Microsoft pero dirige a un sitio externo.",
      microsoftPhishingPattern: "La combinación de remitente ajeno a Microsoft y solicitud de verificación indica alta probabilidad de phishing.",
      brandImpersonation: "El correo menciona {brand} pero enlaza a un dominio no relacionado.",
      transactionalNotice: "El mensaje parece un aviso transaccional o comprobante, no una solicitud de acceso a la cuenta.",
    }
  };

  let _lang = "en";

  function t(key, params) {
    const dict = messages[_lang] || messages.en;
    let msg = (key in dict) ? dict[key] : (messages.en[key] ?? key);
    if (params) {
      for (const [k, v] of Object.entries(params)) {
        msg = msg.replace(`{${k}}`, v);
      }
    }
    return msg;
  }

  function setLang(lang) {
    if (messages[lang]) _lang = lang;
  }

  function getLang() { return _lang; }

  function loadLang() {
    return new Promise(resolve => {
      chrome.storage.local.get("mailsafe_lang", result => {
        const lang = result.mailsafe_lang || "en";
        setLang(lang);
        resolve(lang);
      });
    });
  }

  function saveLang(lang) {
    setLang(lang);
    return new Promise(resolve => {
      chrome.storage.local.set({ mailsafe_lang: lang }, resolve);
    });
  }

  return { t, setLang, getLang, loadLang, saveLang };
})();
