import React, { useEffect, useState } from 'react';
import { Download, Terminal, Server, Cloud, Box, ExternalLink, Check, Copy } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || '';

function CodeBlock({ children, id }) {
  const [copied, setCopied] = useState(false);
  const doCopy = () => {
    navigator.clipboard.writeText(children);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div className="relative group">
      <pre className="bg-zinc-900 border border-zinc-800 p-3 text-xs mono text-emerald-400 overflow-x-auto whitespace-pre-wrap break-all">{children}</pre>
      <button
        onClick={doCopy}
        data-testid={id ? `copy-${id}` : undefined}
        className="absolute top-2 right-2 p-1 border border-zinc-700 bg-zinc-950 text-zinc-500 hover:text-emerald-500 opacity-0 group-hover:opacity-100 transition-opacity"
      >
        {copied ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
      </button>
    </div>
  );
}

function Section({ icon: Icon, title, children, testid }) {
  return (
    <div className="border border-zinc-800 bg-zinc-950" data-testid={testid}>
      <div className="p-4 border-b border-zinc-800 flex items-center gap-2">
        <Icon className="w-4 h-4 text-emerald-500" />
        <h3 className="text-sm font-semibold text-zinc-50 tracking-tight uppercase mono">{title}</h3>
      </div>
      <div className="p-4 space-y-3">{children}</div>
    </div>
  );
}

export default function Deploy() {
  const tarballUrl = '/takeover-scanner-v6.tar.gz';
  const [tarballInfo, setTarballInfo] = useState({ size: null, lastModified: null });

  useEffect(() => {
    // HEAD request to show accurate size + last-modified so user can verify freshness
    fetch(tarballUrl, { method: 'HEAD', cache: 'no-store' })
      .then((r) => {
        const size = Number(r.headers.get('content-length') || 0);
        const lm = r.headers.get('last-modified');
        setTarballInfo({ size, lastModified: lm });
      })
      .catch(() => {});
  }, []);

  const fmtSize = (b) => (b ? `${(b / 1024 / 1024).toFixed(1)} MB` : '~500 KB');

  return (
    <div className="max-w-5xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-zinc-50 tracking-tight flex items-center gap-2">
          <Download className="w-6 h-6 text-emerald-500" /> Download & Deploy
        </h1>
        <p className="text-xs mono text-zinc-500 mt-1">
          Package the full app (CyberScope v7 + Takeover) for Kali Linux, VPS, Docker, or free hosting.
        </p>
      </div>

      {/* Download */}
      <div className="border border-red-500/40 bg-gradient-to-br from-red-500/10 via-zinc-950 to-zinc-950 p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="text-[10px] mono uppercase tracking-widest text-red-500 mb-1">Latest — v7.1 CyberScope Weaponized</div>
            <h2 className="text-xl font-bold text-zinc-50">takeover-scanner-v6.tar.gz</h2>
            <p className="text-xs mono text-zinc-400 mt-1">
              v7.5 · 995+ payloads · 35 modules · API/OAuth/Mobile/Web3 scanners · AI FP Predictor · Deep Crawler · Attack Chain Builder · Strict Verifier (zero false positives) · Bulk Operations · CLI + Chrome Extension · Docker · systemd
            </p>
            <p className="text-[10px] mono text-zinc-500 mt-2" data-testid="tarball-info">
              Size: <span className="text-emerald-500">{fmtSize(tarballInfo.size)}</span>
              {tarballInfo.lastModified && (
                <> · Updated: <span className="text-emerald-500">{tarballInfo.lastModified}</span></>
              )}
            </p>
          </div>
          <a
            href={tarballUrl + '?v=' + Date.now()}
            download="takeover-scanner-v6.tar.gz"
            data-testid="download-tarball-btn"
            className="flex items-center gap-2 px-6 py-3 bg-red-500 hover:bg-red-600 text-white font-bold mono text-sm uppercase tracking-widest transition-colors"
          >
            <Download className="w-4 h-4" /> Download Latest
          </a>
        </div>
      </div>

      {/* Kali / Ubuntu / Debian */}
      <Section icon={Terminal} title="1. Kali / Ubuntu / Debian (Local)" testid="section-local">
        <p className="text-xs mono text-zinc-400">تشغيل محلي على Kali Linux — استخدم هذه الأوامر بالضبط:</p>
        <CodeBlock id="kali">{`# Download from this dashboard, then:
tar -xzf takeover-scanner-v6.tar.gz
cd takeover-scanner-v6
chmod +x install.sh start.sh stop.sh
./install.sh          # ⚠️ Run this FIRST — it creates venv + installs everything
./start.sh            # Then this. Save the admin password shown by install.sh
# Open: http://localhost:3000`}</CodeBlock>
        <div className="text-[10px] mono text-yellow-400">
          ⚠️ إذا رأيت خطأ <span className="bg-zinc-900 px-1">venv/bin/activate: No such file or directory</span> فذلك يعني أنك تخطّيت <span className="bg-zinc-900 px-1">./install.sh</span> — نفّذه أولاً.
        </div>
      </Section>

      {/* Docker */}
      <Section icon={Box} title="2. Docker (الأسهل)" testid="section-docker">
        <p className="text-xs mono text-zinc-400">تشغيل عبر Docker Compose (MongoDB + Backend + Frontend في حاوية واحدة):</p>
        <CodeBlock id="docker">{`tar -xzf takeover-scanner-v6.tar.gz
cd takeover-scanner-v6
# Optional: edit env vars in docker-compose.yml (JWT_SECRET, ADMIN_PASSWORD)
docker compose up -d --build
# Open: http://localhost:3000
# Stop: docker compose down`}</CodeBlock>
      </Section>

      {/* VPS */}
      <Section icon={Server} title="3. VPS (Contabo / Hetzner / Oracle Free Tier)" testid="section-vps">
        <p className="text-xs mono text-zinc-400">
          نشر على VPS Ubuntu 22.04 مع تشغيل دائم عبر systemd + HTTPS عبر Nginx + Certbot:
        </p>
        <CodeBlock id="vps">{`# SSH to your VPS
scp takeover-scanner-v6.tar.gz root@YOUR_VPS_IP:/opt/
ssh root@YOUR_VPS_IP

cd /opt && tar -xzf takeover-scanner-v6.tar.gz
mv takeover-scanner-v6 /opt/takeover-scanner-v6
cd /opt/takeover-scanner-v6

# ✋ IMPORTANT: Point frontend to public IP BEFORE running install.sh
echo "REACT_APP_BACKEND_URL=http://YOUR_VPS_IP:8001" > frontend/.env

chmod +x install.sh start.sh
./install.sh
./start.sh

# Open firewall ports
ufw allow 3000/tcp && ufw allow 8001/tcp

# Access: http://YOUR_VPS_IP:3000`}</CodeBlock>
        <p className="text-xs mono text-zinc-400 mt-3">Persistent service via systemd (see systemd/*.service):</p>
        <CodeBlock id="systemd">{`sudo cp systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now takeover-backend takeover-frontend`}</CodeBlock>
        <p className="text-xs mono text-zinc-400 mt-3">Nginx + HTTPS via Let&apos;s Encrypt:</p>
        <CodeBlock id="nginx">{`sudo apt install nginx certbot python3-certbot-nginx
sudo cp nginx.conf /etc/nginx/sites-available/takeover
# Edit "your-domain.com" in the file, then:
sudo ln -s /etc/nginx/sites-available/takeover /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d your-domain.com`}</CodeBlock>
      </Section>

      {/* Free Hosting */}
      <Section icon={Cloud} title="4. Free Hosting (Render / Railway / Fly.io)" testid="section-cloud">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="border border-zinc-800 bg-zinc-900 p-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-emerald-500 font-bold mono text-xs">Render.com</span>
              <span className="text-[9px] mono text-zinc-500">مجاني دائماً</span>
            </div>
            <ol className="text-[11px] mono text-zinc-400 list-decimal list-inside space-y-1">
              <li>ادفع الكود إلى GitHub</li>
              <li>Render → New Blueprint → اختر ملف render.yaml</li>
              <li>MongoDB → استخدم <a href="https://cloud.mongodb.com" target="_blank" rel="noopener noreferrer" className="text-emerald-500 underline">Atlas Free (M0)</a></li>
              <li>عيّن MONGO_URL في Render env</li>
            </ol>
          </div>
          <div className="border border-zinc-800 bg-zinc-900 p-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-emerald-500 font-bold mono text-xs">Railway.app</span>
              <span className="text-[9px] mono text-zinc-500">500 ساعة/شهر</span>
            </div>
            <ol className="text-[11px] mono text-zinc-400 list-decimal list-inside space-y-1">
              <li>railway login && railway init</li>
              <li>أضف MongoDB plugin (مدمج مجاني)</li>
              <li>Deploy backend + frontend (Dockerfile مرفق)</li>
            </ol>
          </div>
          <div className="border border-zinc-800 bg-zinc-900 p-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-emerald-500 font-bold mono text-xs">Fly.io</span>
              <span className="text-[9px] mono text-zinc-500">3 أجهزة مجانية</span>
            </div>
            <ol className="text-[11px] mono text-zinc-400 list-decimal list-inside space-y-1">
              <li>curl -L https://fly.io/install.sh | sh</li>
              <li>fly auth signup</li>
              <li>cd backend && fly launch --dockerfile ../Dockerfile.backend</li>
              <li>MongoDB via Atlas Free</li>
            </ol>
          </div>
          <div className="border border-zinc-800 bg-zinc-900 p-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-emerald-500 font-bold mono text-xs">Oracle Cloud Free</span>
              <span className="text-[9px] mono text-zinc-500">4 أجهزة مجاناً للأبد</span>
            </div>
            <ol className="text-[11px] mono text-zinc-400 list-decimal list-inside space-y-1">
              <li>سجّل: cloud.oracle.com (يحتاج بطاقة للتحقق فقط)</li>
              <li>أنشئ Ampere ARM instance (24GB RAM مجاناً)</li>
              <li>اتبع خطوات VPS أعلاه</li>
            </ol>
          </div>
        </div>
        <div className="text-[10px] mono text-zinc-500 mt-2">
          راجع الملف <span className="bg-zinc-900 px-1">DEPLOY_FREE_HOSTING.md</span> داخل الحزمة للتفاصيل الكاملة.
        </div>
      </Section>

      {/* v7.5 · CLI + Chrome Extension */}
      <Section icon={Terminal} title="5. CLI Tool (سطر الأوامر مباشرة)" testid="section-cli">
        <p className="text-xs mono text-zinc-400">
          نفّذ الفحص من الطرفية مباشرة — نفس المحرك، بدون واجهة:
        </p>
        <CodeBlock id="cli">{`# من داخل مجلد takeover-scanner-v6
python3 cyberscope_cli.py version
python3 cyberscope_cli.py list-modules

# فحص متوسط لموقع معين وحفظ التقرير بصيغة JSON
python3 cyberscope_cli.py scan https://example.com \\
        --depth medium \\
        --json report.json

# تحديد وحدات معينة فقط (Batch 3)
python3 cyberscope_cli.py scan target.com \\
        --modules api_security,oauth_saml,mobile_backend,web3 \\
        --depth deep -v`}</CodeBlock>
        <p className="text-[10px] mono text-zinc-500">
          لتثبيت أمر عام <span className="text-emerald-400">cyberscope</span> في PATH:
          <span className="bg-zinc-900 px-1 mx-1">sudo ln -s $PWD/cyberscope_cli.py /usr/local/bin/cyberscope</span>
        </p>
      </Section>

      <Section icon={Box} title="6. Chrome Extension (فحص التبويب الحالي بضغطة)" testid="section-chrome">
        <p className="text-xs mono text-zinc-400">
          إضافة كروم لإطلاق فحص فوري على أي صفحة تزورها:
        </p>
        <CodeBlock id="chrome">{`# داخل مجلد takeover-scanner-v6/chrome-extension
# 1. افتح: chrome://extensions/
# 2. فعّل "Developer mode" (أعلى اليمين)
# 3. Load unpacked → اختر مجلد chrome-extension/
# 4. الأيقونة ستظهر في شريط الأدوات
# 5. اضبط "Backend URL" على http://localhost:8001
# 6. اضغط "Launch scan" — سيفتح لك لوحة التحكم تلقائياً`}</CodeBlock>
        <p className="text-[10px] mono text-zinc-500">
          يدعم أيضاً كليك يمين على أي صفحة →
          <span className="text-emerald-400"> CyberScope: Scan this page</span>
        </p>
      </Section>

      {/* v7.6 · CI/CD integration */}
      <Section icon={Terminal} title="7. CI/CD Integration (GitHub Actions / GitLab)" testid="section-cicd">
        <p className="text-xs mono text-zinc-400">
          دمج CyberScope في خط CI/CD الخاص بك — فشل البناء تلقائياً عند اكتشاف ثغرات:
        </p>
        <div className="flex gap-2 flex-wrap mb-3">
          <a
            href={`${(process.env.REACT_APP_BACKEND_URL || '').replace(/\/$/, '')}/api/ci/github-action.yml?depth=shallow&fail_on_severity=high`}
            data-testid="download-github-action"
            className="flex items-center gap-2 px-3 py-1.5 border border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10 mono text-xs uppercase tracking-widest"
          >
            <Download className="w-3 h-3" /> GitHub Actions
          </a>
          <a
            href={`${(process.env.REACT_APP_BACKEND_URL || '').replace(/\/$/, '')}/api/ci/gitlab-ci.yml?depth=shallow&fail_on_severity=high`}
            data-testid="download-gitlab-ci"
            className="flex items-center gap-2 px-3 py-1.5 border border-zinc-700 text-zinc-300 hover:text-emerald-400 hover:border-emerald-500/40 mono text-xs uppercase tracking-widest"
          >
            <Download className="w-3 h-3" /> GitLab CI
          </a>
        </div>
        <CodeBlock id="cicd">{`# نسخة github-action.yml في .github/workflows/
mv ~/Downloads/cyberscope.yml .github/workflows/cyberscope.yml
git add .github/workflows/cyberscope.yml && git commit -m "add cyberscope scan"

# الفحص سيعمل تلقائياً عند كل push/PR
# سيفشل البناء إذا اكتشف أي ثغرة high أو أعلى`}</CodeBlock>
        <p className="text-[10px] mono text-zinc-500 mt-2">
          يمكن تخصيص الهدف والعمق ومستوى الفشل عبر query params:
          <code className="bg-zinc-900 px-1 mx-1">?target=https://staging.example.com&amp;depth=medium&amp;fail_on_severity=medium</code>
        </p>
      </Section>

      {/* Security */}
      <div className="border border-yellow-500/40 bg-yellow-500/5 p-4">
        <div className="text-xs mono uppercase tracking-widest text-yellow-400 mb-2">⚠️ أمان النشر (مهم!)</div>
        <ul className="text-xs mono text-zinc-300 space-y-1 list-disc list-inside">
          <li>غيّر كلمة مرور Admin فوراً بعد التثبيت</li>
          <li>قيّد CORS_ORIGINS إلى دومينك فقط (لا تترك <span className="text-red-400">*</span>)</li>
          <li>استخدم Nginx + Basic Auth أو Cloudflare للحماية من سوء الاستخدام</li>
          <li>افتح فقط 80/443 عبر HTTPS، لا تعرّض 3000/8001 مباشرة على الإنترنت</li>
          <li>قانونياً: استخدم فقط على الأنظمة المُصرَّح لك باختبارها كتابياً</li>
        </ul>
      </div>
    </div>
  );
}
