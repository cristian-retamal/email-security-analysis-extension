window.MailSafeAnalysis = (() => {
  const _t = (key, params) => window.MailSafeI18n?.t(key, params) ?? key;

  const TRUSTED_DOMAINS = [
    "edu",
    "k12",
    "jordandistrict.org",
    "schooldistrict",
    "gandt.jordandistrict.org",
    "cogat.com"
  ];

  const urgencyPattern = /(urgente|inmediatamente|act(ú|u)a ahora|cuenta (suspendida|bloqueada)|última oportunidad|pago pendiente|verifica tu cuenta|verify|suspended|urgent|immediately)/i;
  const asksSecretsPattern = /(contrase(ñ|n)a|password|c(ó|o)digo|otp|token|gift card|tarjeta regalo)/i;
  const impersonationWordsPattern = /(microsoft|outlook|hotmail|live)/i;
  const accountThreatsPattern = /(suspendida|confirmar|verifica|cerrar|bloqueada|account|confirmación)/i;
  const credentialHarvestPattern = /(verificar cuenta|confirmar su cuenta|valida(r)? sus datos|validar sus datos|inicie sesión|restablecer contraseña|actualice su cuenta|verify your account|validate your account)/i;
  const bankNoticePattern = /(transferencia|transferencia recibida|transferencia enviada|dep(ó|o)sito|abono|cargo|movimiento(s)?|operaci(ó|o)n|comprobante|pago recibido|pago aplicado|spei|clabe|interbancaria|bank transfer|wire transfer|payment received|transaction alert|transaction notice)/i;
  const riskyMoneyRequestPattern = /(realiza(r)? una transferencia|env(í|i)e dinero|wire now|urgent wire|gift card|tarjeta regalo|western union|moneygram)/i;
  const officialMicrosoftDomains = ["microsoft.com", "live.com", "outlook.com", "hotmail.com"];
  const specialSecondLevelTlds = new Set([
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.au", "net.au", "org.au",
    "co.nz", "org.nz",
    "com.mx", "org.mx",
    "co.jp", "ne.jp", "or.jp"
  ]);
  const freeHostingDomains = [
    "weebly.com",
    "wixsite.com",
    "blogspot.com",
    "wordpress.com",
    "sites.google.com",
    "github.io",
    "000webhostapp.com",
    "web.app",
    "firebaseapp.com"
  ];
  const suspiciousHostnameKeywords = [
    "login", "verify", "secure", "account", "update",
    "confirm", "signin", "auth", "wallet", "banking"
  ];
  const brandMap = {
    Microsoft: ["microsoft.com", "live.com", "outlook.com", "hotmail.com"],
    Google: ["google.com", "gmail.com"],
    PayPal: ["paypal.com"],
    Amazon: ["amazon.com"],
    Apple: ["apple.com", "icloud.com"]
  };
  const userContentPlatforms = [
    "sites.google.com",
    "github.io",
    "blogspot.com",
    "wordpress.com",
    "wixsite.com",
    "weebly.com",
    "000webhostapp.com",
    "web.app",
    "firebaseapp.com"
  ];
  const brandUnsafeSubplatforms = {
    Google: ["sites.google.com"],
    Microsoft: [],
    PayPal: [],
    Amazon: [],
    Apple: []
  };
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
  const redirectors = new Set([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy", "rebrand.ly",
    "lnkd.in", "l.facebook.com", "mailchi.mp"
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

  function getRegistrableDomain(host) {
    const normalizedHost = (host || "").toLowerCase().replace(/\.$/, "");
    if (!normalizedHost || looksLikeIpHost(normalizedHost)) return normalizedHost;

    const parts = normalizedHost.split(".").filter(Boolean);
    if (parts.length <= 2) return normalizedHost;

    const lastTwo = parts.slice(-2).join(".");
    const lastThree = parts.slice(-3).join(".");

    if (specialSecondLevelTlds.has(lastTwo) && parts.length >= 3) {
      return lastThree;
    }

    return lastTwo;
  }

  function getParentDomain(host) {
    return getRegistrableDomain(host);
  }

  function isFreeHostingDomain(host) {
    const normalizedHost = (host || "").toLowerCase();
    return freeHostingDomains.some(domain => normalizedHost === domain || normalizedHost.endsWith("." + domain));
  }

  function isUserContentPlatform(host) {
    const normalizedHost = (host || "").toLowerCase();
    return userContentPlatforms.some(platform => normalizedHost === platform || normalizedHost.endsWith("." + platform));
  }

  function hasSuspiciousKeywords(host) {
    const normalizedHost = (host || "").toLowerCase();
    return suspiciousHostnameKeywords.some(keyword => normalizedHost.includes(keyword));
  }

  function hasTooManySubdomains(host) {
    const normalizedHost = (host || "").toLowerCase();
    if (!normalizedHost || looksLikeIpHost(normalizedHost)) return false;

    const parentDomain = getParentDomain(normalizedHost);
    const hostParts = normalizedHost.split(".").filter(Boolean);
    const parentParts = (parentDomain || "").split(".").filter(Boolean);
    return hostParts.length - parentParts.length >= 3;
  }

  function looksSuspiciousDomainShape(host) {
    const normalizedHost = (host || "").toLowerCase();
    if (!normalizedHost || looksLikeIpHost(normalizedHost)) return false;

    return normalizedHost.includes("--") ||
      /\d{5,}/.test(normalizedHost) ||
      hasTooManySubdomains(normalizedHost) ||
      hasSuspiciousKeywords(normalizedHost);
  }

  function isKnownRedirector(host) {
    const normalizedHost = (host || "").toLowerCase();
    return redirectors.has(normalizedHost);
  }

  function enrichLinks(links) {
    const safeLinks = Array.isArray(links) ? links : [];
    return safeLinks.map(link => {
      const normalized = normalizeLinkHref
        ? normalizeLinkHref(link.href)
        : {
            effectiveHref: link.href,
            effectiveDomain: getDomain(link.href)
          };
      const host = (normalized.effectiveDomain || "").toLowerCase();
      const effectiveHost = host;
      const registrableDomain = getRegistrableDomain(host);
      return {
        ...link,
        fullHost: host,
        host,
        registrableDomain,
        parentDomain: registrableDomain,
        effectiveHref: normalized.effectiveHref || link.href,
        effectiveHost,
        effectiveParentDomain: getRegistrableDomain(effectiveHost),
        isShortener: isShortener(host),
        isIp: looksLikeIpHost(host),
        isPunycode: hasPunycode(host),
        isFreeHosting: isFreeHostingDomain(host),
        isUserContentPlatform: isUserContentPlatform(host),
        suspiciousShape: looksSuspiciousDomainShape(host),
        isRedirector: isKnownRedirector(host)
      };
    });
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

  function isAllowedBrandDomain(domain, allowedDomains) {
    if (!domain) return false;
    return allowedDomains.some(allowed => domain === allowed || domain.endsWith("." + allowed));
  }

  function isBrandSubplatform(brand, host) {
    const normalizedHost = (host || "").toLowerCase();
    const unsafeHosts = brandUnsafeSubplatforms[brand] || [];
    return unsafeHosts.some(unsafeHost => normalizedHost === unsafeHost || normalizedHost.endsWith("." + unsafeHost));
  }

  function isBrandOwnedDomain(brand, host, registrableDomain) {
    const normalizedHost = (host || "").toLowerCase();
    const normalizedDomain = (registrableDomain || "").toLowerCase();
    const allowedDomains = brandMap[brand] || [];

    if (!isAllowedBrandDomain(normalizedDomain, allowedDomains)) {
      return false;
    }

    if (isBrandSubplatform(brand, normalizedHost)) {
      return false;
    }

    return true;
  }

  function detectBrandImpersonation(body, links) {
    const bodyText = (body || "").toLowerCase();
    const enrichedLinks = Array.isArray(links) ? links : [];

    for (const [brand, domains] of Object.entries(brandMap)) {
      if (!bodyText.includes(brand.toLowerCase())) continue;

      const actionableLinks = enrichedLinks.filter(link =>
        (link.effectiveHost || link.host) &&
        !link.isIp
      );

      if (actionableLinks.length === 0) continue;

      const hasOfficialBrandLink = actionableLinks.some(link => {
        const hostToCompare = link.effectiveHost || link.host;
        const domainToCompare = link.effectiveParentDomain || link.parentDomain;
        return isBrandOwnedDomain(brand, hostToCompare, domainToCompare);
      });

      const hasClearlyUnrelatedLink = actionableLinks.some(link => {
        const hostToCompare = link.effectiveHost || link.host;
        const domainToCompare = link.effectiveParentDomain || link.parentDomain;
        if (isBrandOwnedDomain(brand, hostToCompare, domainToCompare)) return false;
        if (link.isRedirector && !link.effectiveParentDomain) return false;
        if (isBrandSubplatform(brand, hostToCompare)) return true;
        return !!domainToCompare && !isAllowedBrandDomain(domainToCompare, domains);
      });

      if (!hasOfficialBrandLink && hasClearlyUnrelatedLink) {
        return brand;
      }

      if (actionableLinks.some(link =>
        isBrandSubplatform(brand, link.effectiveHost || link.host)
      )) {
        return brand;
      }
    }

    return null;
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
    const normalizedLinks = enrichLinks(links);
    const uniqueHosts = uniq(normalizedLinks.map(link => link.host).filter(Boolean));

    for (const link of normalizedLinks) {
      const host = link.host;
      if (!host) continue;

      if (link.isIp) {
        score += 40;
        findings.push({ level: "red", msg: _t("ipLink") });
      }
      if (link.isShortener) {
        score += 25;
        findings.push({ level: "red", msg: _t("shortenedLink") });
      }
      if (link.isPunycode) {
        score += 30;
        findings.push({ level: "red", msg: _t("punycodeLink") });
      }
      if (link.isFreeHosting) {
        score += 20;
        findings.push({ level: "red", msg: _t("freeHostingLink") });
      }
      if (link.suspiciousShape) {
        score += 12;
        findings.push({ level: "yellow", msg: _t("suspiciousDomain") });
      }
      if (link.isRedirector && !link.isShortener) {
        score += 12;
        findings.push({ level: "yellow", msg: _t("redirectorLink") });
      }

      const mismatchCheck = shouldFlagDomainMismatch(link.text || "", link.href);
      if (mismatchCheck.shouldFlag) {
        const looksInstitutional =
          TRUSTED_DOMAINS.some(d => host.endsWith(d)) ||
          host.includes(".edu") ||
          host.includes(".k12");

        if (!looksInstitutional) {
          score += 25;
          findings.push({ level: "red", msg: _t("linkTextMismatch") });
        } else {
          score += 5;
          findings.push({ level: "yellow", msg: _t("institutionalMismatch") });
        }
      }
    }

    if (urgencyPattern.test(subject) || urgencyPattern.test(body)) {
      if (links.length > 0) {
        score += 25;
        findings.push({ level: "red", msg: _t("urgencyWithLinks") });
      } else {
        score += 10;
        findings.push({ level: "yellow", msg: _t("urgencyAlone") });
      }
    }

    if (asksSecretsPattern.test(subject) || asksSecretsPattern.test(body)) {
      score += 25;
      findings.push({ level: "red", msg: _t("asksSecrets") });
    }

    if (links.length >= 5) {
      score += 10;
      findings.push({ level: "yellow", msg: _t("manyLinks") });
    }

    const bodyText = (email.bodyExcerpt || "").trim();
    const veryShort = bodyText.length > 0 && bodyText.length < 60;
    if (veryShort && links.length > 0) {
      score += 10;
      findings.push({ level: "yellow", msg: _t("shortWithLink") });
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
      normalizedLinks.every(link => !link.parentDomain || domainsMatch(link.parentDomain, senderDomain));
    const looksLikeLegitTransactionalNotice =
      looksLikeBankNotice &&
      !asksToValidateAccount &&
      !asksForRiskyMoneyAction &&
      !mentionsMicrosoftBrand &&
      !suspiciousHostedTextDomain &&
      (normalizedLinks.length === 0 || linksMatchSenderDomain);

    if (mentionsMicrosoftBrand && senderDomain && !isOfficialMicrosoftDomain(senderDomain)) {
      score += 40;
      findings.push({ level: "red", msg: _t("microsoftImpersonation") });
    }

    if (asksToValidateAccount) {
      score += 30;
      findings.push({ level: "red", msg: _t("accountVerification") });
    }

    if (suspiciousHostedTextDomain) {
      score += 35;
      findings.push({ level: "red", msg: _t("freeHostingInContent") });
    }

    if (
      mentionsMicrosoftBrand &&
      mentionsAccountThreat
    ) {
      if (externalTextDomains.length > 0) {
        score += 50;
        findings.push({ level: "red", msg: _t("microsoftExternalLink") });
      }
    }

    if (mentionsMicrosoftBrand && asksToValidateAccount && senderDomain && !isOfficialMicrosoftDomain(senderDomain)) {
      score += 25;
      findings.push({ level: "red", msg: _t("microsoftPhishingPattern") });
    }

    const impersonatedBrand = detectBrandImpersonation(email.bodyExcerpt || "", normalizedLinks);
    if (impersonatedBrand) {
      score += 40;
      findings.push({ level: "red", msg: _t("brandImpersonation", { brand: impersonatedBrand }) });
    }

    if (looksLikeLegitTransactionalNotice) {
      score = Math.max(0, score - 20);
      findings.push({ level: "yellow", msg: _t("transactionalNotice") });
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
      reasons.push(_t("defaultReason"));
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

