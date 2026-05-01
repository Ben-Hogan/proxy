'use strict';

const express = require('express');
const cheerio = require('cheerio');

const app = express();
const PORT = process.env.PORT || 3000;

// ── helpers ───────────────────────────────────────────────────────────────────

function resolveUrl(base, href) {
  if (!href) return null;
  try {
    return new URL(href, base).href;
  } catch {
    return null;
  }
}

function proxyHref(url) {
  return `/proxy?url=${encodeURIComponent(url)}`;
}

const STRIP_RESPONSE_HEADERS = new Set([
  'content-security-policy',
  'content-security-policy-report-only',
  'x-frame-options',
  'x-content-type-options',
  'strict-transport-security',
  'content-encoding',  // fetch auto-decompresses; we must not re-declare it
  'content-length',    // we rewrite content so length changes
  'transfer-encoding',
  'expect-ct',
  'permissions-policy',
  'cross-origin-embedder-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
]);

const SKIP_ATTR_PREFIXES = ['data:', 'javascript:', 'mailto:', 'blob:', '#', 'tel:', 'about:'];

function shouldSkip(val) {
  if (!val) return true;
  return SKIP_ATTR_PREFIXES.some(p => val.startsWith(p));
}

function rewriteAttr($el, attr, base) {
  const val = $el.attr(attr);
  if (shouldSkip(val)) return;
  const resolved = resolveUrl(base, val);
  if (resolved) $el.attr(attr, proxyHref(resolved));
}

function rewriteSrcset(srcset, base) {
  return srcset.split(',').map(part => {
    const trimmed = part.trim();
    const spaceIdx = trimmed.search(/\s/);
    const url  = spaceIdx === -1 ? trimmed : trimmed.slice(0, spaceIdx);
    const desc = spaceIdx === -1 ? ''       : trimmed.slice(spaceIdx);
    if (shouldSkip(url)) return part;
    const resolved = resolveUrl(base, url);
    return resolved ? proxyHref(resolved) + desc : part;
  }).join(', ');
}

function rewriteCss(css, base) {
  css = css.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, (m, q, u) => {
    if (shouldSkip(u)) return m;
    const r = resolveUrl(base, u);
    return r ? `url(${q}${proxyHref(r)}${q})` : m;
  });
  css = css.replace(/@import\s+(['"])([^'"]+)\1/gi, (m, q, u) => {
    if (shouldSkip(u)) return m;
    const r = resolveUrl(base, u);
    return r ? `@import ${q}${proxyHref(r)}${q}` : m;
  });
  return css;
}

// Injected into every proxied HTML page. Intercepts navigation, fetch, XHR,
// history mutations, and form submissions so SPA navigation stays proxied.
// Uses JSON.stringify for safe URL embedding and string-based injection to
// avoid cheerio entity-encoding script content.
function injectedScript(baseUrl) {
  const baseJson = JSON.stringify(baseUrl)
    .replace(/<\/script>/gi, '<\\/script>')
    .replace(/<!--/g, '<\\!--');
  return `<script>(function(){var BASE=${baseJson},P='/proxy?url=';`
    + `function r(u){if(!u||/^(data:|blob:|javascript:)/.test(u))return u;`
    + `try{return P+encodeURIComponent(new URL(u,BASE).href);}catch(e){return u;}}`
    + `var _f=window.fetch;`
    + `window.fetch=function(i,o){if(typeof i==='string')i=r(i);else if(i&&i.url){var u=r(i.url);if(u!==i.url)i=new Request(u,i);}return _f.call(this,i,o);};`
    + `var _X=window.XMLHttpRequest;`
    + `window.XMLHttpRequest=function(){var x=new _X(),_o=x.open.bind(x);x.open=function(m,u){_o(m,r(u));};return x;};`
    + `function wh(fn){return function(s,t,u){if(u&&typeof u==='string'&&u.indexOf('/proxy')){try{u=P+encodeURIComponent(new URL(u,BASE).href);}catch(e){}}return fn.call(history,s,t,u);};}`
    + `history.pushState=wh(history.pushState);history.replaceState=wh(history.replaceState);`
    + `document.addEventListener('click',function(e){var el=e.target.closest('a[href]');if(!el)return;var h=el.getAttribute('href');if(!h||h[0]==='#'||/^(javascript:|mailto:|tel:)/.test(h))return;e.preventDefault();try{location.href=P+encodeURIComponent(new URL(h,BASE).href);}catch(x){}},true);`
    + `document.addEventListener('submit',function(e){var f=e.target,a=f.getAttribute('action')||BASE,m=(f.method||'get').toUpperCase();try{var u=new URL(a,BASE);if(m==='GET'){new FormData(f).forEach(function(v,k){u.searchParams.append(k,v);});e.preventDefault();location.href=P+encodeURIComponent(u.href);}else{f.action=P+encodeURIComponent(u.href);}}catch(x){}},true);`
    + `})();<\/script>`;
}

// ── HTML rewriting ────────────────────────────────────────────────────────────

function rewriteHtml(html, base) {
  const $ = cheerio.load(html, { decodeEntities: false });

  // Remove <base> so relative URLs resolve against our proxy URL
  $('base').remove();

  // href attributes
  $('a[href], link[href]').each((_, el) => rewriteAttr($(el), 'href', base));

  // src attributes
  $('script[src], img[src], iframe[src], video[src], audio[src], source[src], track[src], embed[src], frame[src]').each((_, el) => {
    rewriteAttr($(el), 'src', base);
  });

  // srcset
  $('[srcset]').each((_, el) => {
    const s = $(el).attr('srcset');
    if (s) $(el).attr('srcset', rewriteSrcset(s, base));
  });

  // data attribute (object/applet)
  $('object[data], applet[data]').each((_, el) => rewriteAttr($(el), 'data', base));

  // form action
  $('form[action]').each((_, el) => rewriteAttr($(el), 'action', base));

  // meta refresh
  $('meta[http-equiv="refresh"]').each((_, el) => {
    const content = $(el).attr('content') || '';
    const m = content.match(/^(\d+;\s*url=)(.+)$/i);
    if (m) {
      const r = resolveUrl(base, m[2].trim());
      if (r) $(el).attr('content', m[1] + proxyHref(r));
    }
  });

  // inline styles
  $('[style]').each((_, el) => {
    const s = $(el).attr('style');
    if (s) $(el).attr('style', rewriteCss(s, base));
  });

  // <style> blocks
  $('style').each((_, el) => {
    const css = $(el).html();
    if (css) $(el).html(rewriteCss(css, base));
  });

  let out = $.html();

  // Inject via string replace so cheerio never touches the script content
  const headMatch = out.match(/<head[^>]*>/i);
  if (headMatch) {
    const idx = out.indexOf(headMatch[0]) + headMatch[0].length;
    out = out.slice(0, idx) + injectedScript(base) + out.slice(idx);
  } else {
    out = injectedScript(base) + out;
  }

  return out;
}

// ── landing page ──────────────────────────────────────────────────────────────

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
</style>
</head>
<body>
<div class="card">
  <h1>Proxy</h1>
  <p>Browse any website through this proxy.</p>
  <div class="row">
    <input id="u" type="text" placeholder="https://example.com" autofocus>
    <button onclick="go()">Go</button>
  </div>
  <p class="tip">You can also append a URL as a hash: <code>this-domain.com#https://site.com</code></p>
</div>
<script>
function go(){
  var u=document.getElementById('u').value.trim();
  if(!u)return;
  if(!/^https?:\/\//i.test(u))u='https://'+u;
  window.location.href='/proxy?url='+encodeURIComponent(u);
}
document.getElementById('u').addEventListener('keydown',function(e){if(e.key==='Enter')go();});
var h=location.hash.slice(1);
if(h){
  if(!/^https?:\/\//i.test(h))h='https://'+h;
  document.getElementById('u').value=h;
  go();
}
</script>
</body>
</html>`;

// ── routes ────────────────────────────────────────────────────────────────────

app.get('/', (_req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(LANDING);
});

async function handleProxy(req, res) {
  const targetUrl = req.query.url;
  console.log(`[proxy] ${req.method} ${targetUrl || '(no url)'}`);
  if (!targetUrl) return res.redirect('/');

  let parsedUrl;
  try {
    parsedUrl = new URL(targetUrl);
  } catch {
    return res.status(400).send('Invalid URL');
  }

  const headers = {
    'User-Agent':      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept':          req.headers['accept'] || 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
  };

  if (req.headers['cookie'])   headers['Cookie']        = req.headers['cookie'];
  if (req.headers['referer'])  headers['Referer']        = req.headers['referer'];
  if (req.headers['content-type']) headers['Content-Type'] = req.headers['content-type'];

  const fetchOptions = {
    method:  req.method,
    headers,
    redirect: 'follow',
    signal:  AbortSignal.timeout(20000),
  };

  if (!['GET', 'HEAD'].includes(req.method) && req.body instanceof Buffer && req.body.length > 0) {
    fetchOptions.body = req.body;
  }

  try {
    const upstream = await fetch(parsedUrl.href, fetchOptions);
    const contentType = upstream.headers.get('content-type') || 'application/octet-stream';

    // Forward headers, stripping the ones that break proxying
    for (const [key, value] of upstream.headers.entries()) {
      const lower = key.toLowerCase();
      if (STRIP_RESPONSE_HEADERS.has(lower)) continue;
      if (lower === 'set-cookie') {
        // Strip domain/secure so the cookie binds to our proxy origin
        const cleaned = value
          .replace(/;\s*domain=[^;]+/gi, '')
          .replace(/;\s*secure/gi, '')
          .replace(/;\s*samesite=[^;]+/gi, '; SameSite=Lax');
        res.append('Set-Cookie', cleaned);
        continue;
      }
      if (lower === 'location') {
        // Rewrite redirects to go through proxy
        const r = resolveUrl(parsedUrl.href, value);
        if (r) res.setHeader('Location', proxyHref(r));
        continue;
      }
      res.setHeader(key, value);
    }

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('X-Proxied-By', 'proxy');

    if (contentType.includes('text/html')) {
      const html = await upstream.text();
      const finalUrl = upstream.url || parsedUrl.href;
      const rewritten = rewriteHtml(html, finalUrl);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.status(upstream.status).send(rewritten);
    }

    if (contentType.includes('text/css')) {
      const css = await upstream.text();
      const rewritten = rewriteCss(css, parsedUrl.href);
      res.setHeader('Content-Type', contentType.includes('charset') ? contentType : 'text/css; charset=utf-8');
      return res.status(upstream.status).send(rewritten);
    }

    // Binary / everything else — stream as-is
    const buf = await upstream.arrayBuffer();
    return res.status(upstream.status).send(Buffer.from(buf));

  } catch (err) {
    console.error(`[proxy] ${req.method} ${targetUrl} — ${err.message}`);
    const isTimeout = err.name === 'TimeoutError' || err.name === 'AbortError';
    res.status(isTimeout ? 504 : 502).send(`
      <html><body style="font-family:system-ui;padding:40px;background:#0d0d0d;color:#e0e0e0">
      <h2>${isTimeout ? '504 Timeout' : '502 Upstream Error'}</h2>
      <p>${err.message}</p>
      <p><a href="/" style="color:#4a9eff">← Back</a></p>
      </body></html>`);
  }
}

// GET/HEAD go straight through
app.get('/proxy', handleProxy);
app.head('/proxy', handleProxy);

// POST/PUT/PATCH etc. need body parsing first
app.post('/proxy', express.raw({ type: '*/*', limit: '50mb' }), handleProxy);
app.put('/proxy', express.raw({ type: '*/*', limit: '50mb' }), handleProxy);
app.patch('/proxy', express.raw({ type: '*/*', limit: '50mb' }), handleProxy);

app.listen(PORT, () => console.log(`Proxy listening on port ${PORT}`));
