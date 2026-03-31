window.MailSafeAnalysis = (() => {
  const TRUSTED_DOMAINS = [
    "edu",
    "k12",
    "jordandistrict.org",
    "schooldistrict",
    "gandt.jordandistrict.org",
    "cogat.com"
  ];

  const DEFAULT_REASON = "No se detectaron señales claras de riesgo en lo visible.";
  const urgencyPattern = /(urgente|inmediatamente|act(ú|u)a ahora|cuenta (suspendida|bloqueada)|última oportunidad|pago pendiente|verifica tu cuenta|verify|suspended|urgent|immediately)/i;
  const asksSecretsPattern = /(contrase(ñ|n)a|password|c(ó|o)digo|otp|token|gift card|tarjeta regalo)/i;
  const impersonationWordsPattern = /(microsoft|outlook|hotmail|live)/i;
  const accountThreatsPattern = /(suspendida|confirmar|verifica|cerrar|bloqueada|account|confirmación)/i;
  const credentialHarvestPattern = /(verificar cuenta|confirmar su cuenta|valida(r)? sus datos|validar sus datos|inicie sesión|restablecer contraseña|actualice su cuenta|verify your account|validate your account)/i;
  const bankNoticePattern = /(transferencia|transferencia recibida|transferencia enviada|dep(ó|o)sito|abono|cargo|movimiento(s)?|operaci(ó|o)n|comprobante|pago recibido|pago aplicado|spei|clabe|interbancaria|bank transfer|wire transfer|payment received|transaction alert|transaction notice)/i;
  const riskyMoneyRequestPattern = /(realiza(r)? una transferencia|env(í|i)e dinero|wire now|urgent wire|gift card|tarjeta regalo|western union|moneygram)/i;
  const officialMicrosoftDomains = ["microsoft.com", "live.com", "outlook.com", "hotmail.com"];
  const suspiciousHostDomains = [
    "webcindario.com",
    "blogspot.com",
    "wixsite.com",
    "weebly.com",
    "000webhostapp.com"
  ];
  const shorteners = new Set([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy", "rebrand.ly"
  ]);
  const DEBUG_MISMATCH = false;

  const linkNormalizer = window.linkNormalizer || {};
  const normalizeLinkHref =
    typeof linkNormalizer.normalizeLinkHref === "function"
      ? linkNormalizer.normalizeLinkHref.bind(linkNormalizer)
      : null;

  function uniq(arr) {
    return [...new Set(arr)];
  }

  function parseEmlBasic(raw) {
    const parts = raw.split(/\r?\n\r?\n/);
    const headersRaw = parts[0] || "";
    const bodyRaw = parts.slice(1).join("\n\n");

    const subject = (headersRaw.match(/^Subject:\s*(.*)$/gmi)?.[0] || "").replace(/^Subject:\s*/i, "");
    const from = (headersRaw.match(/^From:\s*(.*)$/gmi)?.[0] || "").replace(/^From:\s*/i, "");
    const bodyExcerpt = bodyRaw.replace(/\r?\n/g, "\n").slice(0, 2000);

    const urlRegex = /https?:\/\/[^\s"'<>()]+/gi;
    const urls = bodyRaw.match(urlRegex) || [];
    const links = urls.slice(0, 50).map(u => ({ href: u, text: u }));

    return {
      provider: "eml",
      senderAddress: from.trim(),
      subject: subject.trim(),
      bodyExcerpt,
      links
    };
  }

  function getDomain(urlStr) {
    try {
      const u = new URL(urlStr);
      return u.hostname.toLowerCase();
    } catch {
      return "";
    }
  }

  function getEffectiveDomain(href) {
    if (normalizeLinkHref) {
      try {
        const normalized = normalizeLinkHref(href);
        return (normalized.effectiveDomain || "").toLowerCase();
      } catch {
        // Fallback a getDomain si hay error
      }
    }

    return getDomain(href);
  }

  function extractDomainsFromText(text) {
    const regex = /([a-z0-9-]+\.)+[a-z]{2,}/gi;
    return [...new Set((text || "").match(regex) || [])];
  }

  function looksLikeIpHost(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  }

  function isShortener(host) {
    return shorteners.has(host);
  }

  function hasPunycode(host) {
    return host.includes("xn--");
  }

  function looksLikeUrl(text) {
    text = (text || "").trim().toLowerCase();
    if (!text) return false;

    if (text.includes("http://") || text.includes("https://")) return true;
    if (text.startsWith("www.")) return true;

    if (/^([a-z0-9-]+\.)+[a-z]{2,}(\/.*)?$/.test(text)) {
      const parts = text.split(".");
      if (parts.length === 2) {
        const firstPart = parts[0];
        const genericWords = [
          "página", "page", "sitio", "site", "web", "website",
          "correo", "email", "mail"
        ];
        if (genericWords.includes(firstPart)) return false;
      }
      return true;
    }

    return false;
  }

  function extractDomainFromText(text) {
    text = (text || "").trim().toLowerCase();
    if (!text) return null;

    try {
      if (text.includes("://")) {
        const url = new URL(text);
        return url.hostname;
      }

      const match = text.match(/^(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)/);
      if (match) return match[1];
    } catch {
      // Ignorar errores de parsing
    }

    return null;
  }

  function isGenericAnchorText(text) {
    text = (text || "").trim().toLowerCase();
    if (!text) return false;

    const genericPatterns = [
      "click aquí", "haz clic", "pulsa", "da clic",
      "nuestra página", "nuestra web", "nuestro sitio",
      "sitio web", "página web", "web", "página", "sitio",
      "ver más", "ver detalles", "leer más", "más información",
      "acceder", "acceso", "ir", "visita",
      "revisar", "chequea", "revisa",
      "enlace", "link", "url",
      "documento", "archivo", "descarga",
      "aquí",
      "click here", "click",
      "our website", "our page", "our site",
      "website", "page", "site",
      "see more", "read more", "learn more", "more info",
      "access", "enter",
      "review", "check",
      "link", "url",
      "document", "file", "download",
      "official", "official site"
    ];

    return genericPatterns.some(pattern => text.includes(pattern));
  }

  function domainsMatch(domainA, domainB) {
    if (!domainA || !domainB) return false;

    const normalize = d => d.toLowerCase().replace(/^www\./, "");
    const a = normalize(domainA);
    const b = normalize(domainB);

    if (a === b) return true;
    if (a.endsWith("." + b)) return true;
    if (b.endsWith("." + a)) return true;

    return false;
  }

  function isOfficialMicrosoftDomain(domain) {
    if (!domain) return false;
    return officialMicrosoftDomains.some(official => domain === official || domain.endsWith("." + official));
  }

  function isSuspiciousHostedDomain(domain) {
    if (!domain) return false;
    return suspiciousHostDomains.some(hosted => domain === hosted || domain.endsWith("." + hosted));
  }

  function shouldFlagDomainMismatch(linkText, href) {
    const anchorText = (linkText || "").trim();

    if (!anchorText || !href) {
      return { shouldFlag: false, reason: "missing_data" };
    }

    const normalized = normalizeLinkHref
      ? normalizeLinkHref(href)
      : {
          originalHref: href,
          effectiveHref: href,
          effectiveDomain: getDomain(href),
          wrapperDetected: false,
          wrapperDomain: null
        };

    const effectiveDestinationDomain = normalized.effectiveDomain;
    const debug = {
      anchorText,
      href,
      effectiveDomain: effectiveDestinationDomain,
      wrapperDetected: normalized.wrapperDetected,
      wrapperProvider: normalized.wrapperProvider
    };

    if (!effectiveDestinationDomain) {
      if (DEBUG_MISMATCH) console.log("[MISMATCH] No effective domain found:", debug);
      return { shouldFlag: false, reason: "no_effective_domain", debug };
    }

    if (isGenericAnchorText(anchorText)) {
      if (DEBUG_MISMATCH) console.log("[MISMATCH] Skipped (generic text):", debug);
      return { shouldFlag: false, reason: "generic_text", debug };
    }

    if (looksLikeUrl(anchorText)) {
      const anchorDomain = extractDomainFromText(anchorText);
      debug.anchorDomain = anchorDomain;
      debug.urlLike = true;

      if (anchorDomain && !domainsMatch(anchorDomain, effectiveDestinationDomain)) {
        if (DEBUG_MISMATCH) console.log("[MISMATCH] URL mismatch detected:", debug);
        return {
          shouldFlag: true,
          reason: "url_domain_mismatch",
          debug
        };
      }

      if (DEBUG_MISMATCH) console.log("[MISMATCH] URL-like but matches:", debug);
      return { shouldFlag: false, reason: "url_match", debug };
    }

    if (DEBUG_MISMATCH) console.log("[MISMATCH] Brand text (TODO):", debug);
    return { shouldFlag: false, reason: "brand_text_todo", debug };
  }

  function analyzeLocally(email) {
    const findings = [];
    let score = 0;

    const subject = (email.subject || "").toLowerCase();
    const body = (email.bodyExcerpt || "").toLowerCase();
    const textDomains = extractDomainsFromText(email.bodyExcerpt);
    const links = Array.isArray(email.links) ? email.links : [];
    const senderDomain = (() => {
      const addr = (email.senderAddress || "").toLowerCase();
      const at = addr.lastIndexOf("@");
      return at >= 0 ? addr.slice(at + 1) : "";
    })();
    const normalizedLinks = links.map(link => ({
      ...link,
      host: getEffectiveDomain(link.href)
    }));
    const uniqueHosts = uniq(normalizedLinks.map(link => link.host).filter(Boolean));

    for (const link of normalizedLinks) {
      const host = link.host;
      if (!host) continue;

      if (looksLikeIpHost(host)) {
        score += 40;
        findings.push({ level: "red", msg: "Hay un enlace que apunta a una dirección IP (muy sospechoso)." });
      }
      if (isShortener(host)) {
        score += 25;
        findings.push({ level: "red", msg: "Hay un enlace acortado (puede ocultar el destino real)." });
      }
      if (hasPunycode(host)) {
        score += 30;
        findings.push({ level: "red", msg: "Hay un enlace con dominio extraño (posible suplantación)." });
      }

      const mismatchCheck = shouldFlagDomainMismatch(link.text || "", link.href);
      if (mismatchCheck.shouldFlag) {
        const looksInstitutional =
          TRUSTED_DOMAINS.some(d => host.endsWith(d)) ||
          host.includes(".edu") ||
          host.includes(".k12");

        if (!looksInstitutional) {
          score += 25;
          findings.push({
            level: "red",
            msg: "El texto del enlace no coincide con el sitio real (posible suplantación)."
          });
        } else {
          score += 5;
          findings.push({
            level: "yellow",
            msg: "El enlace apunta a un sitio institucional distinto al texto mostrado."
          });
        }
      }
    }

    if (urgencyPattern.test(subject) || urgencyPattern.test(body)) {
      if (links.length > 0) {
        score += 25;
        findings.push({ level: "red", msg: "Lenguaje de urgencia junto a enlaces (patrón típico de phishing)." });
      } else {
        score += 10;
        findings.push({ level: "yellow", msg: "Lenguaje de urgencia (precaución)." });
      }
    }

    if (asksSecretsPattern.test(subject) || asksSecretsPattern.test(body)) {
      score += 25;
      findings.push({ level: "red", msg: "El mensaje sugiere pedir claves/códigos o dinero (alto riesgo)." });
    }

    if (links.length >= 5) {
      score += 10;
      findings.push({ level: "yellow", msg: "Contiene muchos enlaces (revisa antes de hacer clic)." });
    }

    const bodyText = (email.bodyExcerpt || "").trim();
    const veryShort = bodyText.length > 0 && bodyText.length < 60;
    if (veryShort && links.length > 0) {
      score += 10;
      findings.push({ level: "yellow", msg: "Mensaje muy corto con enlace (patrón común de engaños)." });
    }

    const mentionsMicrosoftBrand =
      impersonationWordsPattern.test(subject) || impersonationWordsPattern.test(body);
    const mentionsAccountThreat =
      accountThreatsPattern.test(subject) || accountThreatsPattern.test(body);
    const asksToValidateAccount =
      credentialHarvestPattern.test(subject) || credentialHarvestPattern.test(body);
    const looksLikeBankNotice =
      bankNoticePattern.test(subject) || bankNoticePattern.test(body);
    const asksForRiskyMoneyAction =
      riskyMoneyRequestPattern.test(subject) || riskyMoneyRequestPattern.test(body);
    const externalTextDomains = textDomains.filter(d => !isOfficialMicrosoftDomain(d));
    const suspiciousHostedTextDomain = externalTextDomains.find(isSuspiciousHostedDomain);
    const linksMatchSenderDomain =
      !!senderDomain &&
      normalizedLinks.length > 0 &&
      normalizedLinks.every(link => !link.host || domainsMatch(link.host, senderDomain));
    const looksLikeLegitTransactionalNotice =
      looksLikeBankNotice &&
      !asksToValidateAccount &&
      !asksForRiskyMoneyAction &&
      !mentionsMicrosoftBrand &&
      !suspiciousHostedTextDomain &&
      (normalizedLinks.length === 0 || linksMatchSenderDomain);

    if (mentionsMicrosoftBrand && senderDomain && !isOfficialMicrosoftDomain(senderDomain)) {
      score += 40;
      findings.push({
        level: "red",
        msg: "El mensaje aparenta ser de Microsoft, pero el remitente no usa un dominio oficial."
      });
    }

    if (asksToValidateAccount) {
      score += 30;
      findings.push({
        level: "red",
        msg: "El correo pide validar o verificar la cuenta, una táctica común de robo de acceso."
      });
    }

    if (suspiciousHostedTextDomain) {
      score += 35;
      findings.push({
        level: "red",
        msg: "Aparece un dominio de hosting gratuito o poco confiable en el contenido del mensaje."
      });
    }

    if (
      mentionsMicrosoftBrand &&
      mentionsAccountThreat
    ) {
      if (externalTextDomains.length > 0) {
        score += 50;
        findings.push({
          level: "red",
          msg: "El correo se hace pasar por Microsoft pero dirige a un sitio externo."
        });
      }
    }

    if (mentionsMicrosoftBrand && asksToValidateAccount && senderDomain && !isOfficialMicrosoftDomain(senderDomain)) {
      score += 25;
      findings.push({
        level: "red",
        msg: "La combinación de remitente ajeno a Microsoft y solicitud de verificación indica alta probabilidad de phishing."
      });
    }

    if (looksLikeLegitTransactionalNotice) {
      score = Math.max(0, score - 20);
      findings.push({
        level: "yellow",
        msg: "El mensaje parece un aviso transaccional o comprobante, no una solicitud de acceso a la cuenta."
      });
    }

    score = Math.min(100, score);

    let verdict = "SAFE";
    let level = "green";

    if (score >= 60) {
      verdict = "MALICIOUS";
      level = "red";
    } else if (score >= 25) {
      verdict = "SUSPICIOUS";
      level = "yellow";
    }

    const ordered = findings
      .sort((a, b) => (a.level === b.level ? 0 : a.level === "red" ? -1 : 1))
      .map(f => f.msg);

    const reasons = uniq(ordered).slice(0, 2);
    if (reasons.length === 0) {
      reasons.push(DEFAULT_REASON);
    }

    return {
      score,
      verdict,
      level,
      reasons,
      findings: uniq(ordered),
      senderDomain,
      linkDomains: uniqueHosts
    };
  }

  return {
    analyzeLocally,
    parseEmlBasic
  };
})();

