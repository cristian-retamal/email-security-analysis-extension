/**
 * linkNormalizer.js
 * 
 * Utilidad centralizada para normalizar URLs y detectar wrappers de email.
 * Maneja proveedores como Safe Links (Outlook), Proofpoint, Mimecast, Barracuda.
 * 
 * Exporta: normalizeLinkHref(href) -> { originalHref, effectiveHref, effectiveDomain, wrapperDetected, wrapperDomain }
 */

/**
 * Detecta si un dominio es un wrapper conocido de proveedores de email
 * @param {string} domain - El dominio a verificar
 * @returns {object} { isWrapper: bool, provider: string | null, domain: string }
 */
function detectEmailLinkWrapper(domain) {
  if (!domain) {
    return { isWrapper: false, provider: null, domain: null };
  }

  const domain_lower = domain.toLowerCase();

  // Mapeo de wrappers conocidos
  const wrappers = {
    "safelinks.protection.outlook.com": "safelinks",
    "urldefense.proofpoint.com": "proofpoint",
    "urldefense.com": "proofpoint",
    "mimecast.com": "mimecast",
    "barracudanetworks.com": "barracuda"
  };

  // Buscar coincidencia (incluyendo subdomios)
  for (const [wrapperDomain, provider] of Object.entries(wrappers)) {
    if (domain_lower.includes(wrapperDomain)) {
      return { isWrapper: true, provider, domain: wrapperDomain };
    }
  }

  return { isWrapper: false, provider: null, domain: null };
}

/**
 * Extrae la URL real desde un wrapper de email
 * @param {string} href - La URL envuelta
 * @param {string} wrapperProvider - Proveedor identificado (ej: "safelinks", "proofpoint")
 * @returns {string | null} URL desenvuelta o null si no se puede extraer
 */
function extractRealUrlFromWrapper(href, wrapperProvider) {
  if (!href || !wrapperProvider) {
    return null;
  }

  try {
    const url_obj = new URL(href);

    // Microsoft Safe Links: parámetro 'url'
    if (wrapperProvider === "safelinks") {
      const url_param = url_obj.searchParams.get("url");
      if (url_param) {
        return url_param;
      }
    }

    // Proofpoint URL Defense: típicamente '?q=' o '?u='
    if (wrapperProvider === "proofpoint") {
      let param = url_obj.searchParams.get("q") || url_obj.searchParams.get("u");
      if (param) {
        return param;
      }
    }

    // Mimecast: parámetro 'url'
    if (wrapperProvider === "mimecast") {
      const url_param = url_obj.searchParams.get("url");
      if (url_param) {
        return url_param;
      }
    }

    // Barracuda: parámetro 'url'
    if (wrapperProvider === "barracuda") {
      const url_param = url_obj.searchParams.get("url");
      if (url_param) {
        return url_param;
      }
    }
  } catch (e) {
    // Error al parsear la URL, retornar null
  }

  return null;
}

/**
 * Extrae el hostname de una URL
 * @param {string} urlString - URL a procesar
 * @returns {string | null} Hostname normalizado o null
 */
function extractHostname(urlString) {
  if (!urlString) {
    return null;
  }

  try {
    // Si no tiene esquema, agregar uno temporal para parsing
    let urlToParse = urlString;
    if (!urlToParse.match(/^https?:\/\//i)) {
      urlToParse = "http://" + urlToParse;
    }

    const url_obj = new URL(urlToParse);
    return url_obj.hostname;
  } catch (e) {
    // Error al parsear
  }

  return null;
}

/**
 * Normaliza una URL/href: detecta wrappers, extrae destino real y calcula dominio efectivo
 * 
 * @param {string} href - La URL a normalizar
 * @returns {object} Objeto con estructura:
 *   {
 *     originalHref: string,           // URL original tal como fue recibida
 *     effectiveHref: string,          // URL real (desenvuelta si era wrapper)
 *     effectiveDomain: string | null, // Hostname del effectiveHref
 *     wrapperDetected: boolean,       // true si fue envuelta
 *     wrapperDomain: string | null,   // Dominio del wrapper (si aplica)
 *     wrapperProvider: string | null  // Proveedor del wrapper ("safelinks", "proofpoint", etc)
 *   }
 */
function normalizeLinkHref(href) {
  const result = {
    originalHref: href || "",
    effectiveHref: href || "",
    effectiveDomain: null,
    wrapperDetected: false,
    wrapperDomain: null,
    wrapperProvider: null
  };

  if (!href) {
    return result;
  }

  try {
    // Paso 1: Extraer dominio de la URL original
    const originalDomain = extractHostname(href);

    // Paso 2: Detectar si es un wrapper
    const wrapperInfo = detectEmailLinkWrapper(originalDomain);

    if (wrapperInfo.isWrapper) {
      result.wrapperDetected = true;
      result.wrapperDomain = wrapperInfo.domain;
      result.wrapperProvider = wrapperInfo.provider;

      // Paso 3: Intentar extraer la URL real del wrapper
      const realUrl = extractRealUrlFromWrapper(href, wrapperInfo.provider);

      if (realUrl) {
        result.effectiveHref = realUrl;

        // Paso 4: Calcular el dominio efectivo desde la URL real
        const effectiveDomain = extractHostname(realUrl);
        result.effectiveDomain = effectiveDomain;
      } else {
        // No se pudo extraer URL real: usar fallback (fail-safe)
        // effectiveHref y effectiveDomain quedan como originales/null para que no se marque riesgo
        result.effectiveDomain = originalDomain;
      }
    } else {
      // No es wrapper: efectivo = original
      result.effectiveDomain = originalDomain;
    }
  } catch (e) {
    // Error durante procesamiento: fail-safe
    result.effectiveDomain = null;
  }

  return result;
}

// Exportar para uso en otros módulos
// Para entorno de extensión Chrome (sin módulos ES6)
if (typeof module !== "undefined" && module.exports) {
  module.exports = { normalizeLinkHref, detectEmailLinkWrapper, extractRealUrlFromWrapper, extractHostname };
}
// Si se incluye como <script>, exponer globalmente
if (typeof window !== "undefined") {
  window.linkNormalizer = { normalizeLinkHref, detectEmailLinkWrapper, extractRealUrlFromWrapper, extractHostname };
}
