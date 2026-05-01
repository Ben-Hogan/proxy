'use strict';

const express = require('express');
const cheerio = require('cheerio');
const http    = require('http');
const { WebSocketServer, WebSocket } = require('ws');
const { Readable } = require('stream');
const { Agent, ProxyAgent, fetch: undiciFetch, setGlobalDispatcher } = require('undici');

const app = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────────────────────────────────────────
// HTTP client — pooled, optionally via residential proxy
// Set OUTBOUND_PROXY=http://user:pass@host:port to route through a clean IP.
// ─────────────────────────────────────────────────────────────────────────────
const OUTBOUND_PROXY = process.env.OUTBOUND_PROXY || '';
const dispatcher = OUTBOUND_PROXY
  ? new ProxyAgent({ uri: OUTBOUND_PROXY, keepAliveTimeout: 30_000, keepAliveMaxTimeout: 60_000 })
  : new Agent({
      keepAliveTimeout: 30_000,
      keepAliveMaxTimeout: 60_000,
      connections: 256,
      pipelining: 1,
      allowH2: true,
    });
setGlobalDispatcher(dispatcher);
const fetchUp = (url, opts) => undiciFetch(url, { dispatcher, ...opts });

if (OUTBOUND_PROXY) console.log(`[proxy] routing upstream through ${OUTBOUND_PROXY.replace(/:\/\/[^@]+@/, '://***@')}`);
else console.log('[proxy] direct outbound (no OUTBOUND_PROXY set)');

// ─────────────────────────────────────────────────────────────────────────────
// header rules
// ─────────────────────────────────────────────────────────────────────────────
const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
]);
const STRIP_RESPONSE = new Set([
  ...HOP_BY_HOP,
  'content-security-policy', 'content-security-policy-report-only',
  'x-frame-options', 'x-content-type-options',
  'strict-transport-security', 'content-encoding', 'content-length',
  'expect-ct', 'permissions-policy',
  'cross-origin-embedder-policy', 'cross-origin-opener-policy', 'cross-origin-resource-policy',
  'report-to', 'nel', 'alt-svc',
]);
const STRIP_REQUEST = new Set([
  ...HOP_BY_HOP, 'host', 'origin', 'referer',
  'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto',
  'x-real-ip', 'cf-connecting-ip', 'cf-ipcountry', 'cf-ray', 'cf-visitor',
  'forwarded', 'true-client-ip',
]);

// ─────────────────────────────────────────────────────────────────────────────
// path encoding helpers
// ─────────────────────────────────────────────────────────────────────────────
function decodeProxyPath(rawUrl) {
  if (!rawUrl.startsWith('/p/')) return null;
  const rest = rawUrl.slice(3);
  if (/^https?:\/\//i.test(rest)) return rest;
  try {
    const d = decodeURIComponent(rest);
    if (/^https?:\/\//i.test(d)) return d;
  } catch {}
  return null;
}
function proxify(url) { return '/p/' + url; }
function safeURL(input, base) { try { return new URL(input, base); } catch { return null; } }

const SKIP_PREFIXES = ['data:', 'blob:', 'javascript:', 'mailto:', 'tel:', 'about:', 'ws:', 'wss:'];
function shouldSkip(v) {
  if (!v) return true;
  if (v[0] === '#') return true;
  for (const p of SKIP_PREFIXES) if (v.startsWith(p)) return true;
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML rewriting via cheerio (full pages) and CSS via regex
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
  return css;
}

// ─────────────────────────────────────────────────────────────────────────────
// Client runtime — injected into every proxied HTML page
// ─────────────────────────────────────────────────────────────────────────────
function clientRuntime(baseUrl, baseOrigin) {
  const j = (v) => JSON.stringify(v)
    .replace(/<\/script>/gi, '<\\/script>')
    .replace(/<!--/g, '<\\!--');
  return `<script>(function(){
"use strict";
var REAL = ${j(baseUrl)};
var REAL_ORIGIN = ${j(baseOrigin)};
var PFX = '/p/';

var _URL = window.URL;
function isProxyPath(p){ return typeof p==='string' && p.indexOf(PFX)===0; }
function toAbs(u){
  if (u==null) return null;
  if (typeof u !== 'string') u = String(u);
  if (!u || u[0]==='#') return null;
  if (/^(data:|blob:|javascript:|mailto:|tel:|about:)/i.test(u)) return null;
  if (isProxyPath(u)) {
    var rest = u.slice(PFX.length);
    if (/^https?:\\/\\//i.test(rest)) return rest;
    try { var d=decodeURIComponent(rest); if(/^https?:\\/\\//i.test(d)) return d; } catch(e){}
    return null;
  }
  if (u.indexOf('//') === 0) return 'https:' + u;
  if (/^https?:\\/\\//i.test(u)) return u;
  try { return new _URL(u, REAL).href; } catch(e){ return null; }
}
function toProxy(u){
  if (u==null) return u;
  var abs = toAbs(u);
  return abs ? PFX + abs : u;
}
function rewriteSrcset(s){
  return s.split(',').map(function(p){
    var t=p.trim(), i=t.search(/\\s/), u=i===-1?t:t.slice(0,i), d=i===-1?'':t.slice(i);
    return toProxy(u)+d;
  }).join(', ');
}

// snapshot
var _Fetch  = window.fetch && window.fetch.bind(window);
var _XHR    = window.XMLHttpRequest;
var _WS     = window.WebSocket;
var _ES     = window.EventSource;
var _Worker = window.Worker;
var _SB     = navigator.sendBeacon && navigator.sendBeacon.bind(navigator);
var _open   = window.open && window.open.bind(window);

// URL constructor: default base = REAL
function PURL(url, base){
  if (base === undefined) base = REAL;
  if (typeof base === 'string' && isProxyPath(base)) base = REAL;
  return new _URL(url, base);
}
PURL.prototype = _URL.prototype;
['createObjectURL','revokeObjectURL','canParse'].forEach(function(m){ if (_URL[m]) PURL[m] = _URL[m].bind(_URL); });
try { Object.defineProperty(window, 'URL', { value: PURL, configurable: true, writable: true }); } catch(e){}

// location spoofing — patch each readable accessor on the real location object
var _loc = window.location;
function curU(){ var u=new _URL(REAL); try{ u.hash=_loc.hash||''; }catch(e){} return u; }
try {
  ['href','origin','protocol','host','hostname','port','pathname','search','hash'].forEach(function(k){
    Object.defineProperty(_loc, k, {
      configurable: true,
      get: function(){ try { return curU()[k]; } catch(e){ return ''; } },
      set: function(v){
        if (k === 'href')  return _loc.assign(toProxy(v));
        if (k === 'hash')  { try { Object.getOwnPropertyDescriptor(Location.prototype, 'hash').set.call(_loc, v); } catch(e){} return; }
        if (k === 'search'){ try { Object.getOwnPropertyDescriptor(Location.prototype, 'search').set.call(_loc, v); } catch(e){} return; }
      }
    });
  });
  var _assign  = Location.prototype.assign  ? Location.prototype.assign.bind(_loc)  : null;
  var _replace = Location.prototype.replace ? Location.prototype.replace.bind(_loc) : null;
  _loc.assign  = function(v){ if (_assign)  _assign(toProxy(v)); };
  _loc.replace = function(v){ if (_replace) _replace(toProxy(v)); };
} catch(e){}

try { Object.defineProperty(document,'URL',         { configurable:true, get:function(){ return REAL; } }); } catch(e){}
try { Object.defineProperty(document,'documentURI', { configurable:true, get:function(){ return REAL; } }); } catch(e){}
try { Object.defineProperty(document,'referrer',    { configurable:true, get:function(){ return ''; } }); } catch(e){}
try { Object.defineProperty(document,'domain',      { configurable:true, get:function(){ return new _URL(REAL).hostname; }, set:function(){} }); } catch(e){}

// fetch
if (_Fetch) {
  window.fetch = function(input, init){
    try {
      if (typeof input === 'string') input = toProxy(input);
      else if (input && typeof input.url === 'string') {
        var p = toProxy(input.url);
        if (p !== input.url) input = new Request(p, input);
      }
    } catch(e){}
    return _Fetch(input, init);
  };
}

// XHR
window.XMLHttpRequest = function(){
  var x = new _XHR();
  var _o = x.open;
  x.open = function(m, u){ arguments[1] = toProxy(u); return _o.apply(x, arguments); };
  return x;
};

// WebSocket — route through /ws/<encoded>
if (_WS) {
  window.WebSocket = function(url, protocols){
    try {
      var abs = url;
      if (typeof url === 'string') {
        if (/^wss?:\\/\\//i.test(url)) abs = url;
        else if (url.indexOf('//')===0) abs = 'wss:' + url;
        else if (url[0]==='/') abs = REAL_ORIGIN.replace(/^http/, 'ws') + url;
        else abs = REAL_ORIGIN.replace(/^http/, 'ws') + '/' + url;
      }
      var here = location.protocol==='https:' ? 'wss:' : 'ws:';
      var routed = here + '//' + location.host + '/ws/' + encodeURIComponent(abs);
      return protocols ? new _WS(routed, protocols) : new _WS(routed);
    } catch(e){ return new _WS(url, protocols); }
  };
  window.WebSocket.prototype = _WS.prototype;
  window.WebSocket.CONNECTING=0; window.WebSocket.OPEN=1; window.WebSocket.CLOSING=2; window.WebSocket.CLOSED=3;
}
if (_ES) { window.EventSource = function(u,i){ return new _ES(toProxy(u),i); }; window.EventSource.prototype=_ES.prototype; }
if (_SB) { navigator.sendBeacon = function(u,d){ return _SB(toProxy(u),d); }; }
if (_open) { window.open = function(u,n,f){ return _open(u?toProxy(u):u, n, f); }; }
if (_Worker) { window.Worker = function(u,o){ try { return new _Worker(toProxy(u), o); } catch(e){ return new _Worker(u,o); } }; window.Worker.prototype = _Worker.prototype; }

// stub service workers
if (navigator.serviceWorker) {
  try {
    navigator.serviceWorker.register = function(){
      return Promise.resolve({
        scope: REAL_ORIGIN+'/', active:null, installing:null, waiting:null,
        update:function(){ return Promise.resolve(); },
        unregister:function(){ return Promise.resolve(true); },
        addEventListener:function(){}, removeEventListener:function(){}
      });
    };
    navigator.serviceWorker.getRegistration  = function(){ return Promise.resolve(undefined); };
    navigator.serviceWorker.getRegistrations = function(){ return Promise.resolve([]); };
  } catch(e){}
}

// history
function wh(fn){ return function(s,t,u){ if (u != null) { try { u = toProxy(u); } catch(e){} } return fn.call(history,s,t,u); }; }
history.pushState    = wh(history.pushState);
history.replaceState = wh(history.replaceState);

// setAttribute hijack
var _setAttr = Element.prototype.setAttribute;
var URL_ATTRS = {src:1, href:1, action:1, data:1, poster:1, formaction:1, 'xlink:href':1};
Element.prototype.setAttribute = function(name, value){
  var n = (name||'').toLowerCase();
  if (URL_ATTRS[n] && value) value = toProxy(value);
  else if (n === 'srcset' && value) value = rewriteSrcset(value);
  return _setAttr.call(this, name, value);
};
var _setAttrNS = Element.prototype.setAttributeNS;
if (_setAttrNS) {
  Element.prototype.setAttributeNS = function(ns, name, value){
    var n = (name||'').toLowerCase();
    if (URL_ATTRS[n] && value) value = toProxy(value);
    return _setAttrNS.call(this, ns, name, value);
  };
}

// property setters
function hijack(proto, prop){
  if (!proto) return;
  try {
    var d = Object.getOwnPropertyDescriptor(proto, prop);
    if (!d || !d.set) return;
    Object.defineProperty(proto, prop, {
      configurable:true,
      get: d.get,
      set: function(v){ d.set.call(this, toProxy(v)); }
    });
  } catch(e){}
}
[['HTMLAnchorElement','href'],['HTMLAreaElement','href'],['HTMLLinkElement','href'],['HTMLBaseElement','href'],
 ['HTMLImageElement','src'],['HTMLScriptElement','src'],['HTMLIFrameElement','src'],
 ['HTMLEmbedElement','src'],['HTMLSourceElement','src'],['HTMLTrackElement','src'],
 ['HTMLAudioElement','src'],['HTMLVideoElement','src'],['HTMLMediaElement','src'],
 ['HTMLFormElement','action'],['HTMLObjectElement','data']
].forEach(function(t){ hijack(window[t[0]] && window[t[0]].prototype, t[1]); });

// click + submit fallback
document.addEventListener('click', function(e){
  var a = e.target && e.target.closest && e.target.closest('a[href]');
  if (!a) return;
  var h = a.getAttribute('href');
  if (!h || h[0]==='#' || /^(javascript:|mailto:|tel:)/i.test(h)) return;
  if (isProxyPath(h)) return;
  e.preventDefault();
  var p = toProxy(h);
  if (a.target === '_blank') window.open(p, '_blank'); else _loc.assign(p);
}, true);
document.addEventListener('submit', function(e){
  var f = e.target;
  if (!f || f.tagName !== 'FORM') return;
  var action = f.getAttribute('action') || REAL;
  var method = (f.method || 'get').toUpperCase();
  if (isProxyPath(action)) return;
  try {
    var u = new _URL(action, REAL);
    if (method === 'GET') {
      var fd = new FormData(f);
      fd.forEach(function(v,k){ u.searchParams.append(k, v); });
      e.preventDefault();
      _loc.assign(toProxy(u.href));
    } else {
      f.action = toProxy(u.href);
    }
  } catch(err){}
}, true);

// anti-detection
try { Object.defineProperty(navigator,'webdriver',{ configurable:true, get:function(){ return false; } }); } catch(e){}
// hide automation traces
try { delete navigator.__proto__.webdriver; } catch(e){}

})();<\/script>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML rewrite (full)
// ─────────────────────────────────────────────────────────────────────────────
function rewriteHtml(html, finalUrl) {
  const $ = cheerio.load(html, { decodeEntities: false });
  const base = finalUrl;

  $('base').remove();

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
  $('[style]').each((_, el) => {
    const s = $(el).attr('style');
    if (s) $(el).attr('style', rewriteCss(s, base));
  });
  $('style').each((_, el) => {
    const css = $(el).html();
    if (css) $(el).html(rewriteCss(css, base));
  });

  // SRI / crossorigin must go — rewritten URLs won't match
  $('[integrity]').removeAttr('integrity');
  $('[crossorigin]').removeAttr('crossorigin');
  // service worker registration in inline scripts → noop
  $('script:not([src])').each((_, el) => {
    const t = $(el).html();
    if (!t) return;
    if (/serviceWorker\s*\.\s*register/.test(t)) {
      $(el).html(t.replace(/navigator\.serviceWorker\.register\s*\(/g, '(function(){return Promise.resolve()})('));
    }
  });

  let out = $.html();

  // string-injection of the runtime — cheerio occasionally mangles script content
  let baseOrigin = base;
  try { baseOrigin = new URL(base).origin; } catch {}
  const runtime = clientRuntime(base, baseOrigin);
  const headMatch = out.match(/<head[^>]*>/i);
  if (headMatch) {
    const idx = out.indexOf(headMatch[0]) + headMatch[0].length;
    out = out.slice(0, idx) + runtime + out.slice(idx);
  } else {
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
  s=(s||'').trim(); if(!s) return '';
  var l=s.toLowerCase();
  if (l.indexOf('http://')===0 || l.indexOf('https://')===0) return s;
  return 'https://'+s;
}
function go(){
  var u=ensureProto(document.getElementById('u').value);
  if(!u) return;
  window.location.href = '/p/' + u;
}
document.getElementById('btn').addEventListener('click', go);
document.getElementById('u').addEventListener('keydown', function(e){ if(e.key==='Enter') go(); });
var h=location.hash.slice(1);
if (h) { document.getElementById('u').value=ensureProto(h); go(); }
</script>
</body>
</html>`;

// ─────────────────────────────────────────────────────────────────────────────
// Express app
// ─────────────────────────────────────────────────────────────────────────────
app.disable('x-powered-by');

app.get('/', (_req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(LANDING);
});

// CORS preflight short-circuit for proxy paths
app.options(/.*/, (req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] || '*');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.status(204).end();
});

// ─────────────────────────────────────────────────────────────────────────────
// Upstream request builder
// ─────────────────────────────────────────────────────────────────────────────
function realisticHeaders(req, parsedUrl) {
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (STRIP_REQUEST.has(k.toLowerCase())) continue;
    if (k.toLowerCase() === 'cookie') continue; // handled below
    headers[k] = v;
  }
  headers['Host']            = parsedUrl.host;
  headers['Origin']          = parsedUrl.origin;
  headers['Referer']         = parsedUrl.origin + '/';
  headers['User-Agent']      = req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
  headers['Accept-Language'] = req.headers['accept-language'] || 'en-US,en;q=0.9';
  headers['Accept-Encoding'] = 'gzip, deflate, br';
  // Sec-CH-UA family — bot detectors check these
  if (!headers['sec-ch-ua'])         headers['sec-ch-ua']         = '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"';
  if (!headers['sec-ch-ua-mobile'])  headers['sec-ch-ua-mobile']  = '?0';
  if (!headers['sec-ch-ua-platform'])headers['sec-ch-ua-platform']= '"Windows"';
  if (!headers['sec-fetch-site'])    headers['sec-fetch-site']    = 'none';
  if (!headers['sec-fetch-mode'])    headers['sec-fetch-mode']    = 'navigate';
  if (!headers['sec-fetch-dest'])    headers['sec-fetch-dest']    = 'document';
  if (!headers['sec-fetch-user'])    headers['sec-fetch-user']    = '?1';

  // forward cookies
  if (req.headers.cookie) headers['Cookie'] = req.headers.cookie;

  // referer: extract real upstream from /p/ path
  if (req.headers.referer) {
    const ref = req.headers.referer;
    const idx = ref.indexOf('/p/');
    if (idx !== -1) {
      const rest = ref.slice(idx + 3);
      try {
        const decoded = /^https?:\/\//i.test(rest) ? rest : decodeURIComponent(rest);
        if (/^https?:\/\//i.test(decoded)) {
          headers['Referer'] = decoded;
          try { headers['Origin'] = new URL(decoded).origin; } catch {}
          headers['sec-fetch-site'] = 'same-origin';
          headers['sec-fetch-mode'] = 'cors';
        }
      } catch {}
    }
  }
  return headers;
}

function sendError(res, code, msg, target) {
  const safe = (s) => String(s||'').replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));
  res.status(code).setHeader('Content-Type','text/html; charset=utf-8').send(`
<!DOCTYPE html><html><body style="font-family:system-ui;padding:40px;background:#0d0d0d;color:#e0e0e0">
<h2 style="color:#fff">${code} ${code===504?'Timeout':'Upstream Error'}</h2>
<pre style="color:#c66;white-space:pre-wrap">${safe(msg)}</pre>
${target?`<p style="color:#666;font-size:.85rem;word-break:break-all">${safe(target)}</p>`:''}
<p><a href="/" style="color:#4a9eff">← Back</a></p>
</body></html>`);
}

async function streamUpstream(targetUrl, req, res) {
  let parsedUrl;
  try { parsedUrl = new URL(targetUrl); }
  catch { return sendError(res, 400, 'Invalid URL', targetUrl); }

  const headers = realisticHeaders(req, parsedUrl);
  const opts = { method: req.method, headers, redirect: 'manual' };
  if (!['GET','HEAD'].includes(req.method)) {
    opts.body = Readable.toWeb(req);
    opts.duplex = 'half';
  }

  let upstream;
  try { upstream = await fetchUp(parsedUrl.href, opts); }
  catch (err) {
    console.error(`[proxy] FAIL ${req.method} ${parsedUrl.href} — ${err.message}`);
    return sendError(res, 502, err.message, parsedUrl.href);
  }

  // headers
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
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Credentials','true');

  if (upstream.status >= 300 && upstream.status < 400 && upstream.headers.get('location')) {
    return res.status(upstream.status).end();
  }

  const ctype = (upstream.headers.get('content-type') || '').toLowerCase();

  if (ctype.includes('text/html')) {
    const html = await upstream.text();
    const rewritten = rewriteHtml(html, upstream.url || parsedUrl.href);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.status(upstream.status).send(rewritten);
  }
  if (ctype.includes('text/css')) {
    const css = await upstream.text();
    res.setHeader('Content-Type', ctype);
    return res.status(upstream.status).send(rewriteCss(css, parsedUrl.href));
  }

  // stream binary
  res.status(upstream.status);
  if (upstream.body) Readable.fromWeb(upstream.body).pipe(res);
  else res.end();
}

// /p/<url> — any method
app.all(/^\/p\/.+/, async (req, res) => {
  const target = decodeProxyPath(req.originalUrl);
  if (!target) return res.redirect('/');
  await streamUpstream(target, req, res);
});

// Referer-based fallback for stray root-relative requests
app.use(async (req, res, next) => {
  if (req.path === '/' || req.path.startsWith('/p/') || req.path.startsWith('/ws/')) return next();
  const ref = req.headers.referer;
  if (!ref) return next();
  const idx = ref.indexOf('/p/');
  if (idx === -1) return next();
  const rest = ref.slice(idx + 3);
  let refUrl;
  try { refUrl = /^https?:\/\//i.test(rest) ? rest : decodeURIComponent(rest); }
  catch { return next(); }
  if (!/^https?:\/\//i.test(refUrl)) return next();
  let origin;
  try { origin = new URL(refUrl).origin; } catch { return next(); }
  await streamUpstream(origin + req.originalUrl, req, res);
});

// ─────────────────────────────────────────────────────────────────────────────
// HTTP + WebSocket
// ─────────────────────────────────────────────────────────────────────────────
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  if (!req.url.startsWith('/ws/')) { socket.destroy(); return; }
  let target;
  try { target = decodeURIComponent(req.url.slice(4)); }
  catch { socket.destroy(); return; }
  if (!/^wss?:\/\//i.test(target)) { socket.destroy(); return; }

  wss.handleUpgrade(req, socket, head, (clientSock) => {
    let upOrigin;
    try { upOrigin = new URL(target.replace(/^ws/, 'http')).origin; } catch { upOrigin = ''; }
    let upstream;
    try {
      upstream = new WebSocket(target, {
        headers: {
          'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0',
          'Origin': upOrigin,
        },
      });
    } catch { clientSock.close(); return; }

    upstream.on('open', () => {
      clientSock.on('message', m => upstream.readyState===WebSocket.OPEN && upstream.send(m));
      clientSock.on('close',   () => upstream.close());
      upstream.on('message',   m => clientSock.readyState===WebSocket.OPEN && clientSock.send(m));
      upstream.on('close',     () => clientSock.close());
    });
    upstream.on('error', err => { console.error('[ws]', err.message); clientSock.close(); });
    clientSock.on('error', () => upstream.close());
  });
});

server.listen(PORT, () => console.log(`Proxy listening on ${PORT}`));
