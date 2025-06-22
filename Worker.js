// ============= [ نظام التوجيه الكمي المحسن - الإصدار النهائي ] ============= 
class QuantumRouter {
  constructor(env) {
    this.env = env;
    this.routes = new Map();
    this.middlewares = [];
  }

  use(mw) {
    this.middlewares.push(mw);
  }
  
  get(path, handler) {
    this.routes.set(`GET:${path}`, handler);
  }
  
  post(path, handler) {
    this.routes.set(`POST:${path}`, handler);
  }
  
  async handle(request) {
    // تطبيق الوسطاء (Middlewares)
    for (const mw of this.middlewares) {
      const result = await mw(request, this.env);
      if (result instanceof Response) return result;
      if (result instanceof Request) request = result;
    }
    
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, '') || '/';
    const method = request.method.toUpperCase();
    const routeKey = `${method}:${path}`;
    
    // فحص المسار الدقيق أولًا
    let handler = this.routes.get(routeKey);
    let params = {};
    
    // إذا لم يتم العثور على معالج، البحث عن مسارات ديناميكية
    if (!handler) {
      handlerLoop:
      for (let [key, fn] of this.routes) {
        const [m, route] = key.split(':');
        if (m !== method) continue;
        
        // مسار بنمط /:param
        if (route.includes('/:')) {
          const routeParts = route.split('/');
          const pathParts = path.split('/');
          
          if (routeParts.length === pathParts.length) {
            let match = true;
            let tempParams = {};
            
            for (let i = 0; i < routeParts.length; i++) {
              if (routeParts[i].startsWith(':')) {
                const name = routeParts[i].slice(1);
                tempParams[name] = pathParts[i]; // لا نستخدم decodeURIComponent
              } else if (routeParts[i] !== pathParts[i]) {
                match = false;
                break;
              }
            }
            
            if (match) {
              handler = fn;
              params = tempParams;
              break handlerLoop;
            }
          }
        }
      }
    }
    
    try {
      if (handler) {
        return await handler({ request, env: this.env, params });
      }
    } catch (error) {
      return this.handleError(error, request);
    }
    
    // صفحة 404
    return new Response(`
      <!DOCTYPE html><html dir="rtl"><head>
        <title>404 - لم يتم العثور على الصفحة</title>
      </head><body style="text-align:center;font-family:system-ui;padding:50px;">
        <h1>404 - الصفحة غير موجودة</h1>
        <p>ربما تبحث عن:</p>
        <ul>
          <li><a href="/best-${params.keyword || 'منتج'}">أفضل ${params.keyword || 'منتج'}</a></li>
          <li><a href="/top-${params.keyword || 'منتج'}-reviews">مراجعات ${params.keyword || 'منتج'}</a></li>
        </ul>
      </body></html>
    `, {
      status: 404,
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  }
  
  handleError(error, request) {
    // تسجيل الخطأ
    const errorId = `err_${Date.now()}`;
    try {
      this.env.ERROR_LOG.put(errorId, JSON.stringify({
        message: error.message, 
        stack: error.stack,
        url: request.url, 
        timestamp: new Date().toISOString()
      }));
    } catch (e) { /* تجاهل أخطاء التسجيل */ }
    
    return new Response(`
      <div style="font-family:system-ui;text-align:center;padding:50px;">
        <h2>🛠 حدث خطأ - جارٍ المحاولة لإصلاحه</h2>
        <p>جاري إعادة تحميل الصفحة...</p>
        <script>setTimeout(()=>location.reload(),3000);</script>
      </div>
    `, {
      status: 500,
      headers: { 
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store'
      }
    });
  }
}

// ============= [ الأمن الكمومي المحسن - الإصدار النهائي ] ============= 
const QuantumSecurity = {
  apply: async (request, env) => {
    const threatScore = request.cf?.threatScore || 0;
    if (threatScore > 5) {
      return new Response("Forbidden", { status: 403, headers: { 'X-Threat-Blocked': 'true' }});
    }
    
    // نظام الحد الأقصى للطلبات (100 طلب/دقيقة لكل IP)
    const ip = request.headers.get('CF-Connecting-IP');
    const key = `rl:${ip}`;
    let data = { count: 1, ts: Date.now() };
    
    const existing = await env.RATE_LIMIT_KV.get(key);
    if (existing) {
      data = JSON.parse(existing);
      if (Date.now() - data.ts < 60000) {
        data.count++;
        if (data.count > 100) {
          return new Response("Too Many Requests", { status: 429 });
        }
      } else {
        data = { count: 1, ts: Date.now() };
      }
    }
    
    await env.RATE_LIMIT_KV.put(key, JSON.stringify(data), { expirationTtl: 61 });
    
    // إضافة رؤوس الأمان
    const headers = new Headers(request.headers);
    headers.set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src * data:; font-src https://fonts.gstatic.com");
    headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    headers.set("X-Content-Type-Options", "nosniff");
    headers.set("X-Frame-Options", "DENY");
    
    return new Request(request, { headers });
  }
};

// ============= [ دالة الهروب من الأحرف الخاصة لمنع هجمات XSS ] =============
const escapeHTML = str => {
  if (typeof str !== 'string') return '';
  return str.replace(/[&<>"']/g, 
    tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[tag] || tag));
};

// ============= [ الذكاء الكوني مع التخزين المؤقت - الإصدار النهائي ] ============= 
class CosmicAI {
  static async generateContent(keyword, env, request) {
    // تنقية وتقييد الكلمة المفتاحية
    const safeKeyword = escapeHTML(keyword.slice(0, 100).replace(/[^ء-يa-zA-Z0-9\- ]/g, '').trim());
    const geo = request.cf.country || 'GLOBAL';
    const cacheKey = `content:${safeKeyword}:${geo}`;
    
    // محاولة استرداد المحتوى من التخزين المؤقت
    const cached = await env.AFFILIATE_KV.get(cacheKey, 'json');
    if (cached) return cached;
    
    // توليد المحتوى عبر الذكاء الاصطناعي
    let contentHTML = '';
    try {
      // استخدام نموذج Llama-3.1-8b من Cloudflare Workers AI
      const chat = await env.AI.run({
        model: "@cf/meta/llama-3.1-8b-instruct",
        messages: [{ 
          role: "user", 
          content: `اكتب مقدمة قصيرة ومفيدة لمراجعة المنتج التالي للمستخدمين في ${geo}: "${safeKeyword}".` 
        }]
      });
      
      // تطبيق الهروب على الناتج لمنع XSS
      contentHTML = `
        <h1>${escapeHTML(safeKeyword)}: الاختيار الذكي للمحترفين</h1>
        <p>${escapeHTML(chat.choices[0].message.content)}</p>
      `;
    } catch (e) {
      // في حال فشل AI، استخدام نص افتراضي
      contentHTML = `
        <h1>${escapeHTML(safeKeyword)}: الاختيار الذكي للمحترفين</h1>
        <p>نعتذر، حدثت مشكلة مؤقتة في توليد المحتوى. يُرجى المحاولة لاحقًا.</p>
      `;
    }
    
    // بيانات SEO ديناميكية
    const seoData = this.generateSEODATA(safeKeyword, geo);
    const result = { content: contentHTML, seoData, geo };
    
    // تخزين النتيجة مع التحكم في الحجم
    const resultStr = JSON.stringify(result);
    if (resultStr.length < 25 * 1024 * 1024) { // أقل من 25MB
      await env.AFFILIATE_KV.put(cacheKey, resultStr, { expirationTtl: 86400 * 5 });
    }
    
    return result;
  }
  
  static generateSEODATA(keyword, geo) {
    const locale = this.getLocale(geo);
    return {
      title: `${escapeHTML(keyword)} | أفضل العروض في ${geo}`,
      metaDescription: `مراجعة شاملة لمنتج ${escapeHTML(keyword)} - أفضل خيارات السوق في ${geo} بدقة عالية.`,
      ogTags: `
        <meta property="og:title" content="مراجعة ${escapeHTML(keyword)}">
        <meta property="og:description" content="أفضل العروض والخيارات لـ ${escapeHTML(keyword)} في ${geo}">
        <meta property="og:image" content="https://yourcdn.com/images/${encodeURIComponent(keyword)}.jpg">
        <meta property="og:locale" content="${locale}">
      `,
      structuredData: `
        <script type="application/ld+json">
        {
          "@context": "https://schema.org",
          "@type": "Product",
          "name": "${escapeHTML(keyword)}",
          "description": "المراجعة الأكثر شمولاً لمنتج ${escapeHTML(keyword)} في ${geo}",
          "brand": "EdgeAffiliate AI",
          "aggregateRating": {
            "@type": "AggregateRating",
            "ratingValue": "4.8",
            "bestRating": "5",
            "ratingCount": "2137"
          }
        }
        </script>
      `
    };
  }
  
  static getLocale(geo) {
    const locales = { SA: 'ar-SA', EG: 'ar-EG', AE: 'ar-AE', default: 'ar' };
    return locales[geo] || locales.default;
  }
}

// ============= [ محرك الربحية الذهبية - الإصدار النهائي ] ============= 
class GoldenProfitSystem {
  static generateCTA(keyword, request, env) {
    const country = request.cf.country || 'US';
    const stores = this.getStoresByCountry(country);
    const mainStore = stores[0];
    const alternatives = stores.slice(1);
    const safeKeyword = encodeURIComponent(keyword);
    
    // تضمين معرفات الأفيلييت من البيئة
    let mainLink = mainStore.link.replace('{keyword}', safeKeyword);
    if (country === 'US') mainLink += `?tag=${env.AMAZON_US_TAG || ''}`;
    else if (country === 'SA') mainLink += `?tag=${env.AMAZON_SA_TAG || ''}`;
    
    // بناء HTML الزر الرئيسي
    let html = `
      <div class="golden-cta" style="background:linear-gradient(135deg,#f6d365 0%,#fda085 100%);border-radius:12px;padding:20px;text-align:center;margin:30px 0;">
        <p class="urgency">⏳ آخر القطع المتبقية بسرعة!</p>
        <a href="${mainLink}" class="cta-btn"
           style="background:#2c3e50;color:#fff;padding:12px 30px;border-radius:30px;text-decoration:none;font-weight:bold;display:inline-block;margin:15px 0;">
           ⚡ اشتري الآن ووفّر 37% مع ضمان 5 سنوات
        </a>
        <div class="trust-badges">
          <img src="https://yourcdn.com/icons/quality.svg" alt="شهادة جودة"> <span>ضمان 100%</span>
        </div>
    `;
    
    // إضافة المتاجر البديلة
    if (alternatives.length) {
      html += `<div class="alternative-stores"><p>أو اشترِ من:</p><ul>`;
      for (const store of alternatives) {
        let link = store.link.replace('{keyword}', safeKeyword);
        if (store.name.includes('Amazon')) {
          if (country === 'US') link += `?tag=${env.AMAZON_US_TAG || ''}`;
          else link += `?tag=${env.AMAZON_GLOBAL_TAG || ''}`;
        }
        html += `<li><a href="${link}" rel="sponsored nofollow">${store.name}</a></li>`;
      }
      html += `</ul></div>`;
    }
    
    html += `</div>`;
    return html;
  }
  
  static getStoresByCountry(country) {
    const data = {
      US: [
        { name: "Amazon US", link: "https://amzn.to/us-{keyword}" },
        { name: "eBay", link: "https://ebay.com/us/{keyword}" },
        { name: "Walmart", link: "https://walmart.com/search?q={keyword}" }
      ],
      SA: [
        { name: "Amazon Saudi", link: "https://amzn.sa/{keyword}" },
        { name: "Noon", link: "https://noon.com/search?q={keyword}" },
        { name: "eXtra", link: "https://extra.com/sa-en/search?text={keyword}" }
      ],
      EG: [
        { name: "Jumia Egypt", link: "https://jumia.eg/{keyword}" },
        { name: "Amazon Egypt", link: "https://amzn.eg/{keyword}" },
        { name: "Souq", link: "https://souq.com/eg-en/{keyword}" }
      ],
      default: [
        { name: "Amazon Global", link: "https://amzn.to/global-{keyword}" },
        { name: "eBay Global", link: "https://ebay.com/{keyword}" }
      ]
    };
    
    return data[country] || data.default;
  }
}

// ============= [ المتصفح الفائق (Loader) ] ============= 
class HyperLoader {
  static generateLoader() {
    return `
      <div class="quantum-loader" style="text-align:center;padding:50px;">
        <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" style="width:80px;height:80px;margin:0 auto 20px;">
          <circle cx="50" cy="50" r="45" fill="none" stroke="#3498db" stroke-width="8"
                  stroke-dasharray="212" stroke-dashoffset="70">
            <animateTransform attributeName="transform" type="rotate" from="0 50 50" to="360 50 50" dur="1.5s" repeatCount="indefinite"/>
          </circle>
        </svg>
        <p style="font-family:system-ui;color:#3498db;font-weight:bold;">⏳ جارٍ توليد المراجعة الذكية...</p>
      </div>
    `;
  }
}

// ============= [ تعريف المسارات ] ============= 
const router = new QuantumRouter(env);
router.use(QuantumSecurity.apply);

// الصفحة الرئيسية
router.get('/', async ({ request, env }) => {
  const html = `
    <!DOCTYPE html><html dir="rtl"><head>
      <meta charset="UTF-8">
      <title>نظام EdgeAffiliate AI</title>
      <style>
        body { font-family: 'Tajawal', sans-serif; line-height:1.6; padding:20px; text-align:center; }
        .input-form { margin-top:30px; }
        .input-form input { padding:10px; width:200px; border:1px solid #ddd; border-radius:4px; }
        .input-form button { padding:10px 20px; background:#3498db; color:white; border:none; border-radius:4px; cursor:pointer; }
        .input-form button:hover { background:#2980b9; }
      </style>
    </head><body>
      <h1>مرحبًا في نظام الربحية الذكي (EdgeAffiliate AI)</h1>
      <p>للبدء، أضف اسم المنتج بعد العنوان في شريط الرابط.</p>
      <form class="input-form" onsubmit="event.preventDefault();location.href='/' + document.getElementById('keyword').value;">
        <input id="keyword" placeholder="اكتب المنتج" required>
        <button type="submit">ابدأ</button>
      </form>
    </body></html>`;
  
  return new Response(html, {
    headers: { 
      'Content-Type': 'text/html; charset=utf-8', 
      'Cache-Control': 'public, max-age=3600' 
    }
  });
});

// مسار توليد المحتوى بناءً على الكلمة المفتاحية
router.get('/:keyword', async ({ params, request, env }) => {
  const { keyword } = params;
  const startTime = Date.now();
  
  // توليد المحتوى الذكي وتوليد CTA بالتوازي
  const [contentData, ctaHTML] = await Promise.all([
    CosmicAI.generateContent(keyword, env, request),
    GoldenProfitSystem.generateCTA(keyword, request, env)
  ]);
  
  const loadTime = Date.now() - startTime;
  
  return new Response(`
    <!DOCTYPE html><html lang="ar" dir="rtl"><head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width,initial-scale=1.0">
      <title>${contentData.seoData.title}</title>
      <meta name="description" content="${contentData.seoData.metaDescription}">
      ${contentData.seoData.ogTags}
      ${contentData.seoData.structuredData}
      <link rel="canonical" href="${request.url}">
      <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;700&display=swap">
      <style>
        body { font-family: 'Tajawal', sans-serif; background:#f8f9fa; color:#333; margin:0 auto; max-width:800px; padding:20px; }
        .neuro-glow { text-shadow:0 0 8px rgba(52,152,219,0.7); color:#2c3e50; }
        .cta-btn:hover { background:#e74c3c !important; transform:translateY(-3px); transition:0.3s; }
        .cosmic-guarantee { background:#fff; border-radius:8px; padding:20px; margin:30px 0; box-shadow:0 2px 10px rgba(0,0,0,0.1); }
        footer { text-align:center; font-size:12px; margin-top:40px; padding-top:20px; border-top:1px solid #eee; }
      </style>
    </head><body>
      ${HyperLoader.generateLoader()}
      <main id="main-content" style="display:none;">
        ${contentData.content}
        ${ctaHTML}
        <section class="cosmic-guarantee">
          <h2>♾️ ضمان لا نهائي للثقة المطلقة</h2>
          <div style="display:flex;gap:20px;justify-content:center;margin-top:20px;flex-wrap:wrap;">
            <div style="flex:1;min-width:200px;text-align:center;">
              <div style="font-size:40px;">♾️</div>
              <h3>ضمان مدى الحياة</h3>
              <p>استبدال أو استرجاع في أي وقت</p>
            </div>
            <div style="flex:1;min-width:200px;text-align:center;">
              <div style="font-size:40px;">🔐</div>
              <h3>حماية البيانات</h3>
              <p>لا نخزن بياناتك الشخصية بتاتًا</p>
            </div>
          </div>
        </section>
      </main>
      <footer>
        <div>⚡ التحميل: ${loadTime}ms | 🔒 الأمان: كمومي | 🌍 البلد: ${request.cf.country || 'GLOBAL'}</div>
        <div><a href="/privacy">سياسة الخصوصية</a> | <a href="/terms">الشروط والأحكام</a></div>
      </footer>
      <script>
        window.addEventListener('load', () => {
          document.querySelector('.quantum-loader').style.display = 'none';
          document.getElementById('main-content').style.display = 'block';
          
          document.querySelectorAll('.cta-btn').forEach(btn => {
            btn.addEventListener('click', () => {
              fetch('/track/conversion', {
                method: 'POST', 
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({ 
                  keyword: "${escapeHTML(keyword)}", 
                  country: "${request.cf.country || 'UNKNOWN'}", 
                  timestamp: new Date().toISOString() 
                })
              });
            });
          });
        });
      </script>
    </body></html>
  `, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'public, max-age=604800',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY'
    }
  });
});

// مسار تسجيل التحويلات
router.post('/track/conversion', async ({ request, env }) => {
  try {
    const data = await request.json();
    const id = `conv_${Date.now()}`;
    await env.CONVERSION_LOG.put(id, JSON.stringify(data));
    return new Response(null, { status: 204 });
  } catch {
    return new Response(null, { status: 400 });
  }
});

// ===== الصادرات =====
export default {
  async fetch(request, env) {
    return router.handle(request);
  }
};
