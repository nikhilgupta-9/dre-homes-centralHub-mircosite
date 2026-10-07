'use strict';
/** Talks to the central hub from the desktop app / CLI. Only creates sites; it can never read leads. */

function normalizeUrl(u) {
  let url;
  try {
    url = new URL(String(u).trim());
  } catch (e) {
    throw new Error('Hub ka address galat hai. Example: https://hub.example.com');
  }
  const local = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) throw new Error('Hub ka address https:// se shuru hona chahiye (SSL zaroori hai).');
  if (url.username || url.password) throw new Error('Hub ke address mein username/password mat daalo.');
  return (url.origin + url.pathname).replace(/\/+$/, '').replace(/\/(index|install|login)\.php$/, '');
}

const looksLikeDomain = (s) => /^(?:www\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(s);

/** @returns {{site_id:number, site_key:string, secret:string, hub_url:string}} */
async function provisionSite({ url, token }, name, { timeoutMs = 15000 } = {}) {
  const base = normalizeUrl(url);
  if (!/^[A-Za-z0-9_-]{20,80}$/.test(String(token || '').trim())) throw new Error('Hub ka token galat hai (hub ke Settings mein se copy karo).');
  const body = { name: String(name).slice(0, 190), ref: 'studio:' + String(name).slice(0, 150) };
  if (looksLikeDomain(name)) body.domain = name;
  let res;
  try {
    res = await fetch(base + '/api/provision.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + String(token).trim() },
      body: JSON.stringify(body),
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (e) {
    throw new Error('Hub se connect nahi hua (' + (e.name === 'TimeoutError' ? 'der lag gayi' : 'internet/address check karo') + ').');
  }
  if (res.status === 401) throw new Error('Hub ne token nahi manaa. Hub ke Settings se naya token lekar yahan daalo.');
  if (res.status === 429) throw new Error('Hub keh raha hai thoda ruko (bahut requests). Thodi der baad try karo.');
  let j = null;
  try {
    j = await res.json();
  } catch (e) {
    /* not json */
  }
  if (!res.ok || !j || !j.ok || !j.site_key || !j.secret) throw new Error('Hub se galat jawab aaya (status ' + res.status + ').');
  return { site_id: j.site_id, site_key: j.site_key, secret: j.secret, hub_url: base };
}

module.exports = { provisionSite, normalizeUrl, looksLikeDomain };
