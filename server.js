'use strict';

const express = require('express');
const cheerio = require('cheerio');
const http    = require('http');
const { WebSocketServer, WebSocket } = require('ws');
const zlib    = require('zlib');
const { Readable } = require('stream');

const app = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

const STRIP_RESPONSE = new Set([
  ...HOP_BY_HOP,
  'content-security-policy',
  'content-security-policy-report-only',
  'x-frame-options',
  'x-content-type-options',
  'strict-transport-security',
  'content-encoding',
  'content-length',
  'expect-ct',
  'permissions-policy',
  'cross-origin-embedder-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'report-to',
  'nel',
]);

const STRIP_REQUEST = new Set([
  ...HOP_BY_HOP,
  'host', 'origin', 'referer',
  'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto',
  'x-real-ip', 'cf-connecting-ip', 'cf-ipcountry', 'cf-ray', 'cf-visitor',
  'forwarded',
]);

// path-prefix encoding: /p/<full-url>
// browser URL-encodes the URL when navigating, Express decodes it
function decodeProxyPath(rawUrl) {
  // rawUrl looks like "/p/https://site.com/path?q=v" or "/p/https%3A%2F%2F..."
  if (!rawUrl.startsWith('/p/')) return null;
  let rest = rawUrl.slice(3);
  // try to detect already-decoded form
  if (/^https?:\/\//i.test(rest)) return rest;
  try {
    const decoded = decodeURIComponent(rest);
    if (/^https?:\/\//i.test(decoded)) return decoded;
  } catch {}
  return null;
}

function proxify(url) {
  // path-style: /p/https://...
  return '/p/' + url;
}

function safeURL(input, base) {
  try { return new URL(input, base); } catch { return null; }
}

const SKIP_PREFIXES = ['data:', 'blob:', 'javascript:', 'mailto:', 'tel:', 'about:', 'ws:', 'wss:'];
function shouldSkip(v) {
  if (!v) return true;
  if (v[0] === '#') return true;
  for (const p of SKIP_PREFIXES) if (v.startsWith(p)) return true;
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML / CSS rewriting
// ─────────────────────────────────────────────────────────────────────────────

function rewriteAttr($el, attr, base) {
  const v = $el.attr(attr);
  if (shouldSkip(v)) return;
  const u = safeURL(v, base);
  if (u) $el.attr(attr, proxify(u.href));
}

function rewriteSrcset(srcset, base) {
  return srcset.split(',').map(part => {
    const t = part.trim();
    const i = t.search(/\s/);
    const url  = i === -1 ? t : t.slice(0, i);
    const desc = i === -1 ? ''  : t.slice(i);
    if (shouldSkip(url)) return part;
    const u = safeURL(url, base);
    return u ? proxify(u.href) + desc : part;
  }).join(', ');
}

function rewriteCss(css, base) {
  css = css.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, (m, q, u) => {
    if (shouldSkip(u)) return m;
    const r = safeURL(u, base);
    return r ? `url(${q}${proxify(r.href)}${q})` : m;
  });
  css = css.replace(/@import\s+(['"])([^'"]+)\1/gi, (m, q, u) => {
    if (shouldSkip(u)) return m;
    const r = safeURL(u, base);
    return r ? `@import ${q}${proxify(r.href)}${q}` : m;
  });
  // @import url(...)  — handled by the first regex
  return css;
}

// ─────────────────────────────────────────────────────────────────────────────
// Injected client runtime
// Intercepts every escape hatch from our path rewriter:
//   - location / document.URL spoofing
//   - fetch / XHR / WebSocket / EventSource / Worker / importScripts
//   - URL constructor + history APIs
//   - dynamic <script>/<link>/<a>/<form>/<iframe> created via JS
//   - service worker registration (stub)
//   - anti-detection: navigator.webdriver, top===self
// ─────────────────────────────────────────────────────────────────────────────

function clientRuntime(baseUrl, baseOrigin) {
  const j = (v) => JSON.stringify(v)
    .replace(/<\/script>/gi, '<\\/script>')
    .replace(/<!--/g, '<\\!--');
  return `<script>(function(){
"use strict";
var REAL = ${j(baseUrl)};
var REAL_ORIGIN = ${j(baseOrigin)};
var PROXY_PREFIX = '/p/';

function isProxyPath(p){ return typeof p==='string' && p.indexOf(PROXY_PREFIX)===0; }
function isAbs(u){ return /^https?:\\/\\//i.test(u) || /^\\/\\//.test(u); }

// Resolve any url-ish thing to an absolute upstream URL string, or null
function toAbs(u){
  if (!u) return null;
  if (typeof u !== 'string') u = String(u);
  if (u[0] === '#') return null;
  if (/^(data:|blob:|javascript:|mailto:|tel:|about:)/i.test(u)) return null;

  // already proxied? extract original
  if (isProxyPath(u)) {
    var rest = u.slice(PROXY_PREFIX.length);
    if (/^https?:\\/\\//i.test(rest)) return rest;
    try { var d = decodeURIComponent(rest); if (/^https?:\\/\\//i.test(d)) return d; } catch(e){}
    return null;
  }
  // protocol-relative
  if (u.indexOf('//') === 0) return 'https:' + u;
  // absolute
  if (isAbs(u)) return u;
  // relative — resolve against REAL
  try { return new _RealURL(u, REAL).href; } catch(e){ return null; }
}

function toProxy(u){
  var abs = toAbs(u);
  if (!abs) return u;
  return PROXY_PREFIX + abs;
}

// ── snapshot real globals before we touch them ──
var _RealURL          = window.URL;
var _RealFetch        = window.fetch && window.fetch.bind(window);
var _RealXHR          = window.XMLHttpRequest;
var _RealWS           = window.WebSocket;
var _RealES           = window.EventSource;
var _RealWorker       = window.Worker;
var _RealSendBeacon   = navigator.sendBeacon && navigator.sendBeacon.bind(navigator);
var _RealOpen         = window.open && window.open.bind(window);
var _RealRegisterSW   = navigator.serviceWorker && navigator.serviceWorker.register;

// ── URL constructor: resolve against REAL when no base given, but return real URL ──
function ProxyURL(url, base){
  if (base === undefined) base = REAL;
  // if base is a proxied URL, swap to REAL
  if (typeof base === 'string' && isProxyPath(base)) base = REAL;
  return new _RealURL(url, base);
}
ProxyURL.prototype = _RealURL.prototype;
ProxyURL.createObjectURL = _RealURL.createObjectURL ? _RealURL.createObjectURL.bind(_RealURL) : undefined;
ProxyURL.revokeObjectURL = _RealURL.revokeObjectURL ? _RealURL.revokeObjectURL.bind(_RealURL) : undefined;
try { Object.defineProperty(window, 'URL', { value: ProxyURL, configurable: true, writable: true }); } catch(e){}

// ── location spoofing ──
// We can't replace window.location wholesale, but we can replace its members.
// Strategy: leave real location alone, but expose a proxy via document/history reads.
var _real_loc = window.location;
function buildFakeLocation(){
  var u = new _RealURL(REAL);
  return {
    href:     u.href,
    origin:   u.origin,
    protocol: u.protocol,
    host:     u.host,
    hostname: u.hostname,
    port:     u.port,
    pathname: u.pathname,
    search:   u.search,
    hash:     u.hash,
    toString: function(){ return u.href; },
    assign:   function(v){ _real_loc.assign(toProxy(v)); },
    replace:  function(v){ _real_loc.replace(toProxy(v)); },
    reload:   function(){ _real_loc.reload(); },
  };
}
// override the readable members of window.location
try {
  ['href','origin','protocol','host','hostname','port','pathname','search','hash'].forEach(function(k){
    var u = new _RealURL(REAL);
    Object.defineProperty(_real_loc, k, {
      configurable: true,
      get: function(){
        // re-read to pick up hash/search changes
        try { var cur = new _RealURL(REAL); cur.hash = window.location.hash || ''; cur.search = window.location.search || cur.search; return cur[k]; } catch(e){ return u[k]; }
      },
      set: function(v){
        if (k === 'href') _real_loc.assign(toProxy(v));
        else if (k === 'hash') _real_loc.hash = v;
        else if (k === 'search') _real_loc.search = v;
        // mutating other parts via location is rare; ignore
      }
    });
  });
  // wrap assign / replace
  var _origAssign  = _real_loc.assign.bind(_real_loc);
  var _origReplace = _real_loc.replace.bind(_real_loc);
  _real_loc.assign  = function(v){ _origAssign(toProxy(v)); };
  _real_loc.replace = function(v){ _origReplace(toProxy(v)); };
} catch(e){ /* some browsers / iframes lock this down */ }

// document.URL / document.documentURI / document.referrer / document.domain
try {
  Object.defineProperty(document, 'URL',          { configurable:true, get: function(){ return REAL; } });
  Object.defineProperty(document, 'documentURI',  { configurable:true, get: function(){ return REAL; } });
  Object.defineProperty(document, 'referrer',     { configurable:true, get: function(){ return ''; } });
  Object.defineProperty(document, 'domain',       { configurable:true, get: function(){ return new _RealURL(REAL).hostname; }, set: function(){} });
} catch(e){}

// ── fetch ──
if (_RealFetch) {
  window.fetch = function(input, init){
    try {
      if (typeof input === 'string') input = toProxy(input);
      else if (input && typeof input.url === 'string') {
        var p = toProxy(input.url);
        if (p !== input.url) input = new Request(p, input);
      }
    } catch(e){}
    return _RealFetch(input, init);
  };
}

// ── XMLHttpRequest ──
window.XMLHttpRequest = function(){
  var x = new _RealXHR();
  var _open = x.open;
  x.open = function(m, u){
    arguments[1] = toProxy(u);
    return _open.apply(x, arguments);
  };
  return x;
};

// ── WebSocket: route through our /ws endpoint ──
if (_RealWS) {
  window.WebSocket = function(url, protocols){
    try {
      var abs = url;
      if (typeof url === 'string') {
        if (/^wss?:\\/\\//i.test(url)) abs = url;
        else if (url.indexOf('//') === 0) abs = (location.protocol === 'https:' ? 'wss:' : 'ws:') + url;
        else if (url[0] === '/') abs = (REAL_ORIGIN.replace(/^http/, 'ws')) + url;
        else abs = (REAL_ORIGIN.replace(/^http/, 'ws')) + '/' + url;
      }
      var wsProxy = (location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + location.host + '/ws/' + encodeURIComponent(abs);
      return protocols ? new _RealWS(wsProxy, protocols) : new _RealWS(wsProxy);
    } catch(e){
      return new _RealWS(url, protocols);
    }
  };
  window.WebSocket.prototype = _RealWS.prototype;
  window.WebSocket.CONNECTING = 0; window.WebSocket.OPEN = 1; window.WebSocket.CLOSING = 2; window.WebSocket.CLOSED = 3;
}

// ── EventSource ──
if (_RealES) {
  window.EventSource = function(url, init){ return new _RealES(toProxy(url), init); };
  window.EventSource.prototype = _RealES.prototype;
}

// ── sendBeacon ──
if (_RealSendBeacon) {
  navigator.sendBeacon = function(url, data){ return _RealSendBeacon(toProxy(url), data); };
}

// ── window.open ──
if (_RealOpen) {
  window.open = function(url, name, features){
    return _RealOpen(url ? toProxy(url) : url, name, features);
  };
}

// ── Worker ── (best-effort: same-origin workers via blob)
if (_RealWorker) {
  window.Worker = function(url, opts){
    try {
      var p = toProxy(url);
      return new _RealWorker(p, opts);
    } catch(e){
      return new _RealWorker(url, opts);
    }
  };
  window.Worker.prototype = _RealWorker.prototype;
}

// ── Service Worker: stub (most games don't need it; bypass keeps things simple) ──
if (navigator.serviceWorker) {
  try {
    navigator.serviceWorker.register = function(){
      return Promise.resolve({
        scope: REAL_ORIGIN + '/',
        active: null, installing: null, waiting: null,
        update: function(){ return Promise.resolve(); },
        unregister: function(){ return Promise.resolve(true); },
        addEventListener: function(){}, removeEventListener: function(){},
      });
    };
  } catch(e){}
}

// ── history ──
function wrapHist(fn){
  return function(state, title, url){
    if (url != null) {
      try { url = toProxy(url); } catch(e){}
    }
    return fn.call(history, state, title, url);
  };
}
history.pushState    = wrapHist(history.pushState);
history.replaceState = wrapHist(history.replaceState);

// ── DOM mutation: intercept dynamic element src/href ──
var origSetAttr = Element.prototype.setAttribute;
Element.prototype.setAttribute = function(name, value){
  var n = (name||'').toLowerCase();
  if ((n === 'src' || n === 'href' || n === 'action' || n === 'data' || n === 'poster' || n === 'formaction') && value) {
    value = toProxy(value);
  } else if (n === 'srcset' && value) {
    value = value.split(',').map(function(p){
      var t=p.trim(), i=t.search(/\\s/), u=i===-1?t:t.slice(0,i), d=i===-1?'':t.slice(i);
      var pr=toProxy(u); return pr+d;
    }).join(', ');
  }
  return origSetAttr.call(this, name, value);
};

// hijack property setters on the relevant elements
['HTMLAnchorElement','HTMLAreaElement','HTMLLinkElement','HTMLBaseElement'].forEach(function(t){
  if (!window[t]) return;
  try {
    var d = Object.getOwnPropertyDescriptor(window[t].prototype, 'href');
    if (d && d.set) {
      Object.defineProperty(window[t].prototype, 'href', {
        configurable:true,
        get: d.get,
        set: function(v){ d.set.call(this, toProxy(v)); }
      });
    }
  } catch(e){}
});
['HTMLImageElement','HTMLScriptElement','HTMLIFrameElement','HTMLEmbedElement','HTMLSourceElement','HTMLAudioElement','HTMLVideoElement','HTMLTrackElement','HTMLMediaElement'].forEach(function(t){
  if (!window[t]) return;
  ['src','currentSrc'].forEach(function(prop){
    try {
      var d = Object.getOwnPropertyDescriptor(window[t].prototype, prop);
      if (d && d.set) {
        Object.defineProperty(window[t].prototype, prop, {
          configurable:true,
          get: d.get,
          set: function(v){ d.set.call(this, toProxy(v)); }
        });
      }
    } catch(e){}
  });
});
try {
  var d = Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, 'action');
  if (d && d.set) {
    Object.defineProperty(HTMLFormElement.prototype, 'action', {
      configurable:true,
      get: d.get,
      set: function(v){ d.set.call(this, toProxy(v)); }
    });
  }
} catch(e){}

// ── click capture as a final fallback for stubborn frameworks ──
document.addEventListener('click', function(e){
  var a = e.target && e.target.closest && e.target.closest('a[href]');
  if (!a) return;
  var h = a.getAttribute('href');
  if (!h || h[0] === '#') return;
  if (/^(javascript:|mailto:|tel:)/i.test(h)) return;
  if (isProxyPath(h)) return; // already rewritten
  e.preventDefault();
  var target = a.getAttribute('target');
  var p = toProxy(h);
  if (target === '_blank') window.open(p, '_blank'); else _real_loc.assign(p);
}, true);

// ── form submit fallback ──
document.addEventListener('submit', function(e){
  var f = e.target;
  if (!f || f.tagName !== 'FORM') return;
  var action = f.getAttribute('action') || REAL;
  var method = (f.method || 'get').toUpperCase();
  if (isProxyPath(action)) return;
  try {
    var u = new _RealURL(action, REAL);
    if (method === 'GET') {
      var fd = new FormData(f);
      fd.forEach(function(v,k){ u.searchParams.append(k, v); });
      e.preventDefault();
      _real_loc.assign(toProxy(u.href));
    } else {
      f.action = toProxy(u.href);
    }
  } catch(err){}
}, true);

// ── anti-detection ──
try { Object.defineProperty(navigator, 'webdriver', { configurable:true, get: function(){ return false; } }); } catch(e){}

})();<\/script>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Full HTML rewrite
// ─────────────────────────────────────────────────────────────────────────────

function rewriteHtml(html, finalUrl) {
  const $ = cheerio.load(html, { decodeEntities: false });
  const base = finalUrl;

  $('base').remove();

  // attribute rewriting
  $('a[href], link[href], use[href], image[href]').each((_, el) => rewriteAttr($(el), 'href', base));
  $('script[src], img[src], iframe[src], frame[src], video[src], audio[src], source[src], track[src], embed[src]').each((_, el) => rewriteAttr($(el), 'src', base));
  $('img[poster], video[poster]').each((_, el) => rewriteAttr($(el), 'poster', base));
  $('object[data]').each((_, el) => rewriteAttr($(el), 'data', base));
  $('form[action]').each((_, el) => rewriteAttr($(el), 'action', base));
  $('button[formaction], input[formaction]').each((_, el) => rewriteAttr($(el), 'formaction', base));

  $('[srcset]').each((_, el) => {
    const v = $(el).attr('srcset');
    if (v) $(el).attr('srcset', rewriteSrcset(v, base));
  });

  // meta refresh
  $('meta[http-equiv]').each((_, el) => {
    const $el = $(el);
    if (($el.attr('http-equiv') || '').toLowerCase() !== 'refresh') return;
    const c = $el.attr('content') || '';
    const m = c.match(/^(\d+\s*;\s*url=)(.+)$/i);
    if (m) {
      const r = safeURL(m[2].trim(), base);
      if (r) $el.attr('content', m[1] + proxify(r.href));
    }
  });

  // inline style
  $('[style]').each((_, el) => {
    const s = $(el).attr('style');
    if (s) $(el).attr('style', rewriteCss(s, base));
  });
  $('style').each((_, el) => {
    const css = $(el).html();
    if (css) $(el).html(rewriteCss(css, base));
  });

  // remove integrity / crossorigin — rewritten URLs won't match the hash
  $('[integrity]').removeAttr('integrity');
  $('[crossorigin]').removeAttr('crossorigin');

  let out = $.html();

  // inject runtime as a string op (cheerio sometimes mangles script content)
  const baseOrigin = (() => { try { return new URL(base).origin; } catch { return base; } })();
  const runtime = clientRuntime(base, baseOrigin);
  const headMatch = out.match(/<head[^>]*>/i);
  if (headMatch) {
    const idx = out.indexOf(headMatch[0]) + headMatch[0].length;
    out = out.slice(0, idx) + runtime + out.slice(idx);
  } else {
    // no <head> — inject right after <html> or at the top
    const htmlMatch = out.match(/<html[^>]*>/i);
    if (htmlMatch) {
      const idx = out.indexOf(htmlMatch[0]) + htmlMatch[0].length;
      out = out.slice(0, idx) + '<head>' + runtime + '</head>' + out.slice(idx);
    } else {
      out = runtime + out;
    }
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Landing page
// ─────────────────────────────────────────────────────────────────────────────

const LANDING = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Proxy</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d0d0d;color:#e0e0e0;font-family:system-ui,-apple-system,sans-serif;
  display:flex;align-items:center;justify-content:center;min-height:100vh;padding:16px}
.card{background:#181818;border:1px solid #2a2a2a;border-radius:14px;padding:40px 36px;
  width:min(520px,100%);box-shadow:0 8px 32px rgba(0,0,0,.5)}
h1{font-size:1.5rem;font-weight:700;margin-bottom:8px;color:#fff;letter-spacing:-.02em}
p{font-size:.875rem;color:#888;margin-bottom:28px}
.row{display:flex;gap:8px}
input{flex:1;padding:11px 14px;background:#222;border:1px solid #333;border-radius:9px;
  color:#e0e0e0;font-size:15px;outline:none;transition:border-color .15s}
input:focus{border-color:#4a9eff}
button{padding:11px 20px;background:#4a9eff;color:#fff;border:none;border-radius:9px;
  font-size:15px;font-weight:600;cursor:pointer;transition:background .15s;white-space:nowrap}
button:hover{background:#3a8eff}
.tip{margin-top:16px;font-size:.8rem;color:#555}
.tip code{background:#222;padding:2px 6px;border-radius:4px;color:#888}
</style>
</head>
<body>
<div class="card">
  <h1>Proxy</h1>
  <p>Browse any website through this proxy.</p>
  <div class="row">
    <input id="u" type="text" placeholder="https://example.com" autofocus>
    <button id="btn">Go</button>
  </div>
  <p class="tip">Append a URL as a hash: <code>this-domain.com#site.com</code></p>
</div>
<script>
function ensureProto(s){
  s = (s||'').trim();
  if (!s) return '';
  var lower = s.toLowerCase();
  if (lower.indexOf('http://') === 0 || lower.indexOf('https://') === 0) return s;
  return 'https://' + s;
}
function go(){
  var u = ensureProto(document.getElementById('u').value);
  if (!u) return;
  window.location.href = '/p/' + u;
}
document.getElementById('btn').addEventListener('click', go);
document.getElementById('u').addEventListener('keydown', function(e){
  if (e.key === 'Enter') go();
});
var h = location.hash.slice(1);
if (h) {
  document.getElementById('u').value = ensureProto(h);
  go();
}
</script>
</body>
</html>`;

// ─────────────────────────────────────────────────────────────────────────────
// Express routes
// ─────────────────────────────────────────────────────────────────────────────

app.disable('x-powered-by');

app.get('/', (_req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(LANDING);
});

// /p/<url> proxy entry — accepts ANY method, streams body for non-GET
function buildUpstreamHeaders(req, parsedUrl) {
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (STRIP_REQUEST.has(k.toLowerCase())) continue;
    headers[k] = v;
  }
  // Realistic browser fingerprint
  headers['Host']            = parsedUrl.host;
  headers['Origin']          = parsedUrl.origin;
  headers['Referer']         = parsedUrl.origin + '/';
  headers['User-Agent']      = req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
  headers['Accept-Language'] = headers['accept-language'] || 'en-US,en;q=0.9';
  headers['Accept-Encoding'] = 'gzip, deflate, br';
  // Forward referrer if it points to a /p/ URL — extract real referrer
  if (req.headers.referer) {
    const ref = req.headers.referer;
    const idx = ref.indexOf('/p/');
    if (idx !== -1) {
      const realRef = ref.slice(idx + 3);
      try {
        const decoded = /^https?:\/\//i.test(realRef) ? realRef : decodeURIComponent(realRef);
        if (/^https?:\/\//i.test(decoded)) headers['Referer'] = decoded;
      } catch {}
    }
  }
  return headers;
}

async function streamUpstream(targetUrl, req, res) {
  let parsedUrl;
  try { parsedUrl = new URL(targetUrl); }
  catch { return res.status(400).send('Invalid URL'); }

  const headers = buildUpstreamHeaders(req, parsedUrl);

  const fetchOpts = {
    method: req.method,
    headers,
    redirect: 'manual',  // we handle redirects so we can rewrite Location
  };
  if (!['GET', 'HEAD'].includes(req.method)) {
    fetchOpts.body = Readable.toWeb(req);
    fetchOpts.duplex = 'half';
  }

  let upstream;
  try {
    upstream = await fetch(parsedUrl.href, fetchOpts);
  } catch (err) {
    console.error(`[proxy] FETCH FAIL ${req.method} ${parsedUrl.href} — ${err.message}`);
    return sendError(res, 502, err.message, parsedUrl.href);
  }

  // copy response headers (filtered)
  for (const [k, v] of upstream.headers.entries()) {
    const lk = k.toLowerCase();
    if (STRIP_RESPONSE.has(lk)) continue;
    if (lk === 'set-cookie') {
      const cleaned = v
        .replace(/;\s*domain=[^;]+/gi, '')
        .replace(/;\s*secure/gi, '')
        .replace(/;\s*samesite=[^;]+/gi, '; SameSite=Lax');
      res.append('Set-Cookie', cleaned);
      continue;
    }
    if (lk === 'location') {
      const r = safeURL(v, parsedUrl.href);
      if (r) res.setHeader('Location', proxify(r.href));
      continue;
    }
    res.setHeader(k, v);
  }
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', '*');
  res.setHeader('Access-Control-Allow-Headers', '*');

  // Manual redirect handling — return the rewritten location
  if (upstream.status >= 300 && upstream.status < 400 && upstream.headers.get('location')) {
    return res.status(upstream.status).end();
  }

  const ctype = (upstream.headers.get('content-type') || '').toLowerCase();

  // HTML — buffer, decompress if needed (fetch does this), rewrite, send
  if (ctype.includes('text/html')) {
    const html = await upstream.text();
    const rewritten = rewriteHtml(html, upstream.url || parsedUrl.href);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(upstream.status).send(rewritten);
  }

  // CSS — same
  if (ctype.includes('text/css')) {
    const css = await upstream.text();
    const rewritten = rewriteCss(css, parsedUrl.href);
    res.setHeader('Content-Type', ctype);
    return res.status(upstream.status).send(rewritten);
  }

  // Everything else — stream straight through
  res.status(upstream.status);
  if (upstream.body) {
    Readable.fromWeb(upstream.body).pipe(res);
  } else {
    res.end();
  }
}

function sendError(res, code, msg, target) {
  res.status(code).setHeader('Content-Type', 'text/html; charset=utf-8').send(`
<!DOCTYPE html><html><body style="font-family:system-ui;padding:40px;background:#0d0d0d;color:#e0e0e0">
<h2>${code} ${code === 504 ? 'Timeout' : 'Upstream Error'}</h2>
<pre style="color:#c66">${(msg||'').replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]))}</pre>
${target ? `<p style="color:#666;font-size:.85rem">${target.replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]))}</p>` : ''}
<p><a href="/" style="color:#4a9eff">← Back</a></p>
</body></html>`);
}

// /p/<url>  — handles all methods, all paths under /p/
app.all(/^\/p\/.+/, async (req, res) => {
  const target = decodeProxyPath(req.originalUrl);
  if (!target) return res.redirect('/');
  console.log(`[${req.method}] ${target}`);
  await streamUpstream(target, req, res);
});

// Referer-based fallback: a proxied page made a relative request that escaped to root.
// e.g. <img src="/foo.png"> on a page where rewriting somehow missed it.
app.use(async (req, res, next) => {
  if (req.path === '/' || req.path.startsWith('/p/') || req.path.startsWith('/ws/')) return next();

  const ref = req.headers.referer;
  if (!ref) return next();
  const idx = ref.indexOf('/p/');
  if (idx === -1) return next();

  const refRest = ref.slice(idx + 3);
  let refUrl;
  try {
    refUrl = /^https?:\/\//i.test(refRest) ? refRest : decodeURIComponent(refRest);
  } catch { return next(); }
  if (!/^https?:\/\//i.test(refUrl)) return next();

  let origin;
  try { origin = new URL(refUrl).origin; } catch { return next(); }

  const target = origin + req.originalUrl;
  console.log(`[fallback] ${req.method} ${req.originalUrl} → ${target}`);
  await streamUpstream(target, req, res);
});

// ─────────────────────────────────────────────────────────────────────────────
// HTTP + WebSocket bridge
// ─────────────────────────────────────────────────────────────────────────────

const server = http.createServer(app);

const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  // path: /ws/<encoded-original-ws-url>
  if (!req.url.startsWith('/ws/')) {
    socket.destroy();
    return;
  }
  const encoded = req.url.slice(4);
  let target;
  try { target = decodeURIComponent(encoded); } catch { socket.destroy(); return; }
  if (!/^wss?:\/\//i.test(target)) { socket.destroy(); return; }

  wss.handleUpgrade(req, socket, head, (clientSock) => {
    let upstream;
    try {
      upstream = new WebSocket(target, {
        headers: {
          'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0',
          'Origin':     new URL(target.replace(/^ws/, 'http')).origin,
        },
      });
    } catch (err) {
      clientSock.close();
      return;
    }

    upstream.on('open', () => {
      clientSock.on('message',  (m) => upstream.readyState === WebSocket.OPEN && upstream.send(m));
      clientSock.on('close',    ()  => upstream.close());
      upstream.on('message',    (m) => clientSock.readyState === WebSocket.OPEN && clientSock.send(m));
      upstream.on('close',      ()  => clientSock.close());
    });
    upstream.on('error', (err) => { console.error('[ws]', err.message); clientSock.close(); });
    clientSock.on('error', () => upstream.close());
  });
});

server.listen(PORT, () => console.log(`Proxy listening on ${PORT}`));
