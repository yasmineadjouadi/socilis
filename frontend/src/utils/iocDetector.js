export function detectInputType(raw) {
  const text = raw.trim();

  if (/^[a-f0-9]{32}$/i.test(text) || /^[a-f0-9]{40}$/i.test(text) || /^[a-f0-9]{64}$/i.test(text))
    return { isIOC: true, type: "hash" };

  if (/^cve-\d{4}-\d{4,}$/i.test(text))
    return { isIOC: true, type: "cve" };

  if (/^https?:\/\/.+/i.test(text))
    return { isIOC: true, type: "url" };

  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(text))
    return { isIOC: true, type: "mail" };

  if (/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(text))
    return { isIOC: true, type: "ip" };

  if (/^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i.test(text))
    return { isIOC: true, type: "ip" };

  if (!text.includes(" ") && /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(text) && !/^\d/.test(text))
    return { isIOC: true, type: "domain" };

  return { isIOC: false, type: null };
}

export function stripIOCPrefix(text) {
  return text.replace(/^\[(?:HASH|IP|URL|DOMAIN|CVE|MAIL)\]\s*/i, "").trim();
}

export const TYPE_LABELS = {
  ip: "Adresse IP", hash: "Hash", url: "URL",
  domain: "Domaine", mail: "Email", cve: "CVE",
};