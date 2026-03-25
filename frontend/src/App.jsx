import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  RadarChart, Radar, PolarGrid, PolarAngleAxis,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from "recharts";

// ─── CONSTANTS ────────────────────────────────────────────────────────────────
const FONTS = `@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;400;500;600;700&family=Orbitron:wght@400;700;900&display=swap');`;

const PRECAUTIONS = {
  Phishing:      ["Avoid clicking suspicious links in emails or messages","Enable Two-Factor Authentication (2FA) on all accounts","Verify email sender domain before responding or clicking","Use browser extensions that detect phishing sites","Report phishing attempts to your IT security team"],
  DDoS:          ["Enable and configure advanced firewall rules immediately","Monitor traffic spikes using IDS/IPS monitoring tools","Implement rate limiting and traffic throttling policies","Use CDN and load balancing for traffic distribution","Contact your ISP to blackhole attack traffic upstream"],
  Malware:       ["Run a full antivirus / anti-malware scan immediately","Keep your OS and all software fully patched and updated","Isolate the affected system from the network","Avoid downloading files from unknown or untrusted sources","Review running processes and startup programs for anomalies"],
  "Brute Force": ["Enable account lockout after N failed login attempts","Enforce a strong password policy organization-wide","Enable CAPTCHA on all public-facing login pages","Implement IP-based rate limiting on authentication endpoints","Enable MFA for all privileged and user accounts"],
};

const ATTACK_COLORS = { Phishing:"#ff3c6e", DDoS:"#ff6b35", Malware:"#a855f7", "Brute Force":"#ffaa00", Normal:"#00ff9d" };

const SEED_LOGS = [
  { id:1, ts:"2026-02-28 08:12:34", ip:"192.168.1.105", port:22,   proto:"TCP",   traffic:850,  logins:15, url:45,  isAttack:true,  attackType:"Brute Force", risk:"HIGH",   conf:94 },
  { id:2, ts:"2026-02-28 08:11:01", ip:"10.0.0.55",    port:80,   proto:"HTTP",  traffic:9500, logins:0,  url:42,  isAttack:true,  attackType:"DDoS",        risk:"HIGH",   conf:91 },
  { id:3, ts:"2026-02-28 08:09:18", ip:"172.16.0.1",   port:443,  proto:"HTTPS", traffic:120,  logins:0,  url:45,  isAttack:false, attackType:"N/A",         risk:"LOW",    conf:85 },
  { id:4, ts:"2026-02-28 08:07:55", ip:"10.0.0.78",    port:443,  proto:"HTTP",  traffic:300,  logins:0,  url:230, isAttack:true,  attackType:"Phishing",    risk:"MEDIUM", conf:88 },
  { id:5, ts:"2026-02-28 08:05:42", ip:"192.168.2.10", port:21,   proto:"FTP",   traffic:180,  logins:0,  url:60,  isAttack:true,  attackType:"Malware",     risk:"MEDIUM", conf:82 },
  { id:6, ts:"2026-02-28 07:58:11", ip:"10.10.0.3",    port:3389, proto:"TCP",   traffic:460,  logins:28, url:55,  isAttack:true,  attackType:"Brute Force", risk:"HIGH",   conf:97 },
  { id:7, ts:"2026-02-28 07:45:03", ip:"192.168.0.50", port:8080, proto:"HTTP",  traffic:92,   logins:0,  url:38,  isAttack:false, attackType:"N/A",         risk:"LOW",    conf:78 },
];

const DEMO_SETS = [
  { ip:"192.168.1.105", port:"22",   proto:"TCP",   traffic:850,  logins:15, url:45  },
  { ip:"10.0.0.55",     port:"80",   proto:"HTTP",  traffic:9500, logins:0,  url:42  },
  { ip:"172.16.0.22",   port:"443",  proto:"HTTPS", traffic:120,  logins:0,  url:42  },
  { ip:"192.168.0.200", port:"21",   proto:"FTP",   traffic:300,  logins:42, url:88  },
  { ip:"10.0.0.78",     port:"443",  proto:"HTTP",  traffic:300,  logins:0,  url:230 },
];

const PROC_STEPS = [
  "Collecting input parameters",
  "Preprocessing & normalizing data",
  "Extracting feature vectors",
  "Running Random Forest model",
  "Classifying attack type",
  "Generating precaution advisory",
];

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function validateIP(ip) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && ip.split('.').every(n => +n <= 255);
}

function nowTS() {
  const d = new Date();
  return d.toISOString().replace("T", " ").slice(0, 19);
}

// ─── STYLES ───────────────────────────────────────────────────────────────────
const css = `
${FONTS}
*,*::before,*::after{margin:0;padding:0;box-sizing:border-box;}
:root{
  --bg:#020b14;--bg2:#040f1c;--panel:#071828;--panel2:#0a1e30;
  --border:#0e3a5c;--accent:#00d4ff;--accent2:#00ff9d;--accent3:#ff3c6e;
  --accent4:#ffaa00;--text:#c8e6f0;--dim:#5a8a9f;
  --glow:0 0 20px rgba(0,212,255,.35);--glow2:0 0 20px rgba(0,255,157,.35);
  --glow3:0 0 20px rgba(255,60,110,.4);
}
body{background:var(--bg);font-family:'Rajdhani',sans-serif;color:var(--text);overflow-x:hidden;}
body::before{content:'';position:fixed;inset:0;
  background-image:linear-gradient(rgba(0,212,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,.025) 1px,transparent 1px);
  background-size:44px 44px;z-index:0;animation:gridMove 22s linear infinite;pointer-events:none;}
body::after{content:'';position:fixed;inset:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.04) 2px,rgba(0,0,0,.04) 4px);
  pointer-events:none;z-index:9998;}
@keyframes gridMove{0%{background-position:0 0}100%{background-position:44px 44px}}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border)}::-webkit-scrollbar-thumb:hover{background:var(--accent)}
.nav{position:fixed;top:0;left:0;right:0;z-index:1000;background:rgba(2,11,20,.92);backdrop-filter:blur(14px);border-bottom:1px solid var(--border);height:64px;display:flex;align-items:center;padding:0 32px;justify-content:space-between;}
.nav-brand{font-family:'Orbitron',monospace;font-size:.78rem;font-weight:900;color:var(--accent);letter-spacing:2px;display:flex;align-items:center;gap:10px;text-shadow:var(--glow);}
.nav-hex{width:34px;height:34px;background:linear-gradient(135deg,var(--accent),var(--accent2));clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);display:flex;align-items:center;justify-content:center;font-size:.8rem;animation:hexPulse 2.5s ease-in-out infinite;}
@keyframes hexPulse{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(.92);opacity:.7}}
.nav-links{display:flex;gap:2px;}
.nav-link{font-family:'Share Tech Mono',monospace;font-size:.72rem;color:var(--dim);padding:8px 18px;border:1px solid transparent;letter-spacing:1.5px;cursor:pointer;transition:all .25s;background:none;user-select:none;}
.nav-link:hover{color:var(--accent);border-color:rgba(0,212,255,.3);background:rgba(0,212,255,.04);}
.nav-link.active{color:var(--accent);border-color:var(--accent);background:rgba(0,212,255,.07);text-shadow:var(--glow);}
.nav-right{display:flex;align-items:center;gap:16px;}
.status-pill{display:flex;align-items:center;gap:8px;font-family:'Share Tech Mono',monospace;font-size:.65rem;color:var(--accent2);}
.status-dot{width:7px;height:7px;background:var(--accent2);border-radius:50%;animation:blink 1.8s ease-in-out infinite;box-shadow:var(--glow2);}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.15}}
.threat-badge{font-family:'Share Tech Mono',monospace;font-size:.6rem;padding:4px 10px;border:1px solid var(--accent3);color:var(--accent3);background:rgba(255,60,110,.08);animation:threatBlink 3s ease-in-out infinite;}
@keyframes threatBlink{0%,100%{opacity:1}50%{opacity:.4}}
.ticker{position:fixed;top:64px;left:0;right:0;z-index:999;background:rgba(4,15,28,.95);border-bottom:1px solid var(--border);height:32px;display:flex;align-items:center;overflow:hidden;}
.ticker-track{white-space:nowrap;animation:tickerScroll 35s linear infinite;font-family:'Share Tech Mono',monospace;font-size:.65rem;color:var(--dim);padding-left:100%;}
@keyframes tickerScroll{0%{transform:translateX(0)}100%{transform:translateX(-100%)}}
.ticker-alert{color:var(--accent3);margin:0 6px;}
.ticker-ok{color:var(--accent2);margin:0 6px;}
.page-root{padding-top:96px;min-height:100vh;position:relative;z-index:1;}
.hero{min-height:calc(100vh - 96px);display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:60px 32px;position:relative;}
.hero-orbit{position:absolute;border-radius:50%;border:1px solid;pointer-events:none;}
.hero-tag{font-family:'Share Tech Mono',monospace;font-size:.68rem;color:var(--accent2);letter-spacing:5px;margin-bottom:18px;text-shadow:var(--glow2);}
.hero-title{font-family:'Orbitron',monospace;font-size:clamp(1.8rem,5.5vw,4rem);font-weight:900;line-height:1.05;background:linear-gradient(135deg,#fff 0%,var(--accent) 45%,var(--accent2) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:22px;}
.hero-sub{font-size:1.1rem;color:var(--dim);max-width:620px;margin:0 auto 40px;line-height:1.75;}
.hero-btns{display:flex;gap:14px;justify-content:center;flex-wrap:wrap;}
.btn-primary{display:inline-flex;align-items:center;gap:8px;padding:14px 36px;background:transparent;border:1px solid var(--accent);color:var(--accent);font-family:'Orbitron',monospace;font-size:.78rem;font-weight:700;letter-spacing:2px;cursor:pointer;transition:all .3s;position:relative;overflow:hidden;}
.btn-primary::after{content:'';position:absolute;inset:0;background:var(--accent);transform:translateX(-101%);transition:.3s;z-index:-1;}
.btn-primary:hover{color:var(--bg);text-shadow:none;}.btn-primary:hover::after{transform:translateX(0);}
.btn-ghost{display:inline-flex;align-items:center;gap:8px;padding:14px 36px;background:transparent;border:1px solid var(--border);color:var(--dim);font-family:'Orbitron',monospace;font-size:.78rem;font-weight:700;letter-spacing:2px;cursor:pointer;transition:.3s;}
.btn-ghost:hover{border-color:var(--accent2);color:var(--accent2);}
.stats-strip{display:flex;justify-content:center;gap:60px;padding:40px 32px;border-top:1px solid var(--border);border-bottom:1px solid var(--border);background:rgba(7,24,40,.7);flex-wrap:wrap;}
.stat-num{font-family:'Orbitron',monospace;font-size:2.4rem;font-weight:900;color:var(--accent);text-shadow:var(--glow);display:block;}
.stat-label{font-family:'Share Tech Mono',monospace;font-size:.62rem;color:var(--dim);letter-spacing:2px;margin-top:4px;}
.threat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1px;padding:0;background:var(--border);}
.threat-card{background:var(--panel);padding:32px;position:relative;overflow:hidden;cursor:default;transition:.35s;}
.threat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--tc,var(--accent));}
.threat-card::after{content:'';position:absolute;inset:0;background:radial-gradient(circle at 0 0,rgba(255,255,255,.03),transparent 60%);opacity:0;transition:.35s;}
.threat-card:hover{transform:translateY(-3px);background:var(--panel2);}.threat-card:hover::after{opacity:1;}
.threat-icon{font-size:2.2rem;margin-bottom:16px;display:block;}
.threat-card h3{font-family:'Orbitron',monospace;font-size:.82rem;letter-spacing:2px;color:var(--tc,var(--accent));margin-bottom:10px;}
.threat-card p{font-size:.9rem;color:var(--dim);line-height:1.65;}
.threat-badge-row{display:flex;gap:8px;margin-top:14px;flex-wrap:wrap;}
.tag{font-family:'Share Tech Mono',monospace;font-size:.6rem;padding:3px 8px;border:1px solid var(--tc,var(--accent));color:var(--tc,var(--accent));opacity:.7;}
.pred-layout{display:grid;grid-template-columns:1fr 1fr;gap:2px;padding:32px;max-width:1400px;margin:0 auto;background:var(--border);}
.panel{background:var(--panel);padding:30px;}
.panel-hdr{display:flex;align-items:center;gap:12px;margin-bottom:26px;padding-bottom:14px;border-bottom:1px solid var(--border);}
.panel-icon{width:36px;height:36px;background:rgba(0,212,255,.08);border:1px solid var(--accent);display:flex;align-items:center;justify-content:center;font-size:1rem;}
.panel-hdr h2{font-family:'Orbitron',monospace;font-size:.82rem;letter-spacing:2.5px;color:var(--accent);}
.panel-hdr .sub{font-family:'Share Tech Mono',monospace;font-size:.62rem;color:var(--dim);margin-left:auto;letter-spacing:1px;}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;}
.field{margin-bottom:16px;}
.field label{display:flex;align-items:center;justify-content:space-between;font-family:'Share Tech Mono',monospace;font-size:.65rem;color:var(--dim);letter-spacing:2px;margin-bottom:7px;}
.field-hint{font-size:.58rem;color:rgba(90,138,159,.5);}
.field input,.field select{width:100%;background:var(--bg2);border:1px solid var(--border);color:var(--text);padding:11px 14px;font-family:'Share Tech Mono',monospace;font-size:.82rem;outline:none;transition:.25s;-webkit-appearance:none;}
.field input:focus,.field select:focus{border-color:var(--accent);box-shadow:inset 0 0 0 1px rgba(0,212,255,.2);}
.field.err input,.field.err select{border-color:var(--accent3);}
.field-err{font-family:'Share Tech Mono',monospace;font-size:.6rem;color:var(--accent3);margin-top:5px;display:none;}
.field.err .field-err{display:block;}
.field select option{background:var(--panel);}
.range-wrap{display:flex;align-items:center;gap:10px;}
.range-wrap input[type=range]{flex:1;-webkit-appearance:none;height:3px;background:var(--border);outline:none;}
.range-wrap input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:14px;height:14px;background:var(--accent);cursor:pointer;border-radius:0;}
.range-val{font-family:'Orbitron',monospace;font-size:.75rem;color:var(--accent);min-width:48px;text-align:right;}
.btn-analyze{width:100%;padding:15px;background:transparent;border:1px solid var(--accent2);color:var(--accent2);font-family:'Orbitron',monospace;font-size:.82rem;font-weight:700;letter-spacing:3px;cursor:pointer;transition:.3s;margin-top:6px;position:relative;overflow:hidden;}
.btn-analyze::after{content:'';position:absolute;inset:0;background:var(--accent2);transform:translateX(-101%);transition:.3s;z-index:-1;}
.btn-analyze:hover{color:var(--bg);}.btn-analyze:hover::after{transform:translateX(0);}
.btn-analyze:disabled{opacity:.4;cursor:not-allowed;pointer-events:none;}
.btn-demo{background:none;border:none;color:var(--dim);font-family:'Share Tech Mono',monospace;font-size:.65rem;cursor:pointer;letter-spacing:1px;text-decoration:underline;margin-top:10px;display:block;text-align:center;transition:.2s;}
.btn-demo:hover{color:var(--accent);}
.res-idle{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:360px;color:var(--dim);font-family:'Share Tech Mono',monospace;font-size:.78rem;text-align:center;gap:14px;}
.res-idle-icon{font-size:3.5rem;opacity:.2;animation:float 3s ease-in-out infinite;}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}
.res-idle p{font-size:.62rem;opacity:.4;letter-spacing:1px;}
.proc-wrap{display:flex;flex-direction:column;align-items:center;gap:20px;padding:40px 20px;}
.proc-ring{width:72px;height:72px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;}
@keyframes spin{to{transform:rotate(360deg)}}
.proc-label{font-family:'Orbitron',monospace;font-size:.8rem;color:var(--accent);letter-spacing:3px;}
.proc-steps{width:100%;max-width:340px;}
.proc-step{display:flex;align-items:center;gap:12px;padding:7px 0;font-family:'Share Tech Mono',monospace;font-size:.72rem;opacity:.25;transition:.4s;}
.proc-step.active{opacity:1;color:var(--accent);}
.proc-step.done{opacity:.8;color:var(--accent2);}
.proc-dot{width:7px;height:7px;border:1px solid currentColor;border-radius:50%;flex-shrink:0;transition:.3s;}
.proc-step.done .proc-dot{background:currentColor;}
.proc-step.active .proc-dot{animation:dotPulse .6s ease-in-out infinite;}
@keyframes dotPulse{0%,100%{transform:scale(1)}50%{transform:scale(1.6)}}
.res-verdict{text-align:center;padding:28px 20px;margin-bottom:20px;border:1px solid;position:relative;overflow:hidden;}
.res-verdict.safe{border-color:var(--accent2);background:rgba(0,255,157,.04);}
.res-verdict.attack{border-color:var(--accent3);background:rgba(255,60,110,.04);}
.res-verdict::before{content:'';position:absolute;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(circle,rgba(255,255,255,.015) 0%,transparent 70%);animation:scanPulse 3s ease-in-out infinite;}
@keyframes scanPulse{0%,100%{transform:scale(.9);opacity:.5}50%{transform:scale(1.1);opacity:1}}
.verdict-lbl{font-family:'Share Tech Mono',monospace;font-size:.62rem;letter-spacing:3px;opacity:.5;margin-bottom:6px;}
.verdict-txt{font-family:'Orbitron',monospace;font-size:1.9rem;font-weight:900;}
.res-verdict.safe .verdict-txt{color:var(--accent2);text-shadow:var(--glow2);}
.res-verdict.attack .verdict-txt{color:var(--accent3);text-shadow:var(--glow3);}
.meta-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:20px;}
.meta-box{background:var(--bg2);border:1px solid var(--border);padding:14px;text-align:center;}
.meta-lbl{font-family:'Share Tech Mono',monospace;font-size:.58rem;color:var(--dim);letter-spacing:2px;display:block;margin-bottom:5px;}
.meta-val{font-family:'Orbitron',monospace;font-size:1rem;font-weight:700;}
.risk-LOW{color:var(--accent2)}.risk-MEDIUM{color:var(--accent4)}.risk-HIGH{color:var(--accent3)}
.conf-bar-wrap{margin-bottom:20px;}
.conf-lbl{display:flex;justify-content:space-between;font-family:'Share Tech Mono',monospace;font-size:.65rem;color:var(--dim);margin-bottom:7px;letter-spacing:1px;}
.conf-track{height:5px;background:var(--border);overflow:hidden;position:relative;}
.conf-fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));transition:width 1.1s cubic-bezier(.4,0,.2,1);box-shadow:0 0 12px rgba(0,212,255,.5);}
.prec-section h3{font-family:'Orbitron',monospace;font-size:.72rem;color:var(--accent4);letter-spacing:2px;margin-bottom:12px;}
.prec-item{display:flex;align-items:flex-start;gap:10px;padding:10px 14px;background:rgba(255,170,0,.04);border-left:2px solid var(--accent4);margin-bottom:7px;font-size:.88rem;animation:slideIn .35s ease forwards;opacity:0;}
@keyframes slideIn{from{opacity:0;transform:translateX(-12px)}to{opacity:1;transform:translateX(0)}}
.prec-item.safe{border-color:var(--accent2);background:rgba(0,255,157,.04);}
.dash-layout{padding:32px;max-width:1400px;margin:0 auto;}
.page-title{font-family:'Orbitron',monospace;font-size:1.1rem;color:var(--accent);text-shadow:var(--glow);letter-spacing:3px;margin-bottom:28px;}
.kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:2px;margin-bottom:2px;background:var(--border);}
.kpi{background:var(--panel);padding:24px 20px;position:relative;overflow:hidden;}
.kpi::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;background:var(--kc,var(--accent));}
.kpi-lbl{font-family:'Share Tech Mono',monospace;font-size:.6rem;color:var(--dim);letter-spacing:2px;margin-bottom:8px;}
.kpi-val{font-family:'Orbitron',monospace;font-size:2rem;font-weight:900;color:var(--kc,var(--accent));text-shadow:0 0 20px var(--kc,var(--accent));}
.kpi-sub{font-family:'Share Tech Mono',monospace;font-size:.6rem;color:var(--dim);margin-top:4px;}
.charts-grid{display:grid;grid-template-columns:1fr 1fr;gap:2px;margin-bottom:2px;background:var(--border);}
.chart-panel{background:var(--panel);padding:24px;}
.chart-title{font-family:'Orbitron',monospace;font-size:.72rem;color:var(--dim);letter-spacing:2px;margin-bottom:18px;}
.radar-chart{grid-column:1/-1;}
.history-panel{background:var(--panel);}
.hist-hdr{display:flex;align-items:center;justify-content:space-between;padding:20px 24px;border-bottom:1px solid var(--border);}
.hist-hdr h2{font-family:'Orbitron',monospace;font-size:.78rem;color:var(--accent);letter-spacing:2px;}
.hist-controls{display:flex;gap:10px;align-items:center;}
.hist-search{background:var(--bg2);border:1px solid var(--border);color:var(--text);padding:7px 12px;font-family:'Share Tech Mono',monospace;font-size:.7rem;outline:none;width:200px;transition:.25s;}
.hist-search:focus{border-color:var(--accent);}
.btn-clear{background:none;border:1px solid var(--accent3);color:var(--accent3);padding:7px 16px;font-family:'Share Tech Mono',monospace;font-size:.65rem;cursor:pointer;letter-spacing:1px;transition:.25s;}
.btn-clear:hover{background:rgba(255,60,110,.1);}
.hist-table{width:100%;border-collapse:collapse;font-family:'Share Tech Mono',monospace;font-size:.72rem;}
.hist-table th{background:var(--panel2);color:var(--dim);font-size:.6rem;letter-spacing:2px;padding:13px 16px;text-align:left;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;transition:.2s;}
.hist-table th:hover{color:var(--accent);}
.hist-table td{padding:12px 16px;border-bottom:1px solid rgba(14,58,92,.45);transition:.2s;}
.hist-table tr:hover td{background:rgba(0,212,255,.025);}
.badge{display:inline-block;padding:2px 9px;font-size:.6rem;letter-spacing:1px;border:1px solid;}
.b-safe{color:var(--accent2);border-color:var(--accent2);background:rgba(0,255,157,.06);}
.b-atk{color:var(--accent3);border-color:var(--accent3);background:rgba(255,60,110,.06);}
.b-low{color:var(--accent2);border-color:rgba(0,255,157,.3);}
.b-medium{color:var(--accent4);border-color:rgba(255,170,0,.3);}
.b-high{color:var(--accent3);border-color:rgba(255,60,110,.3);}
.empty-state{text-align:center;padding:60px;font-family:'Share Tech Mono',monospace;font-size:.78rem;color:var(--dim);}
.pagination{display:flex;align-items:center;justify-content:center;gap:8px;padding:18px;border-top:1px solid var(--border);}
.page-btn{background:none;border:1px solid var(--border);color:var(--dim);width:32px;height:32px;font-family:'Share Tech Mono',monospace;font-size:.7rem;cursor:pointer;transition:.2s;}
.page-btn:hover,.page-btn.active{border-color:var(--accent);color:var(--accent);}
.page-btn:disabled{opacity:.3;cursor:not-allowed;}
.about-layout{padding:60px 32px;max-width:1200px;margin:0 auto;}
.about-hero{text-align:center;margin-bottom:50px;}
.flow-label{font-family:'Share Tech Mono',monospace;font-size:.65rem;color:var(--dim);letter-spacing:2px;margin:0 auto 40px;max-width:900px;line-height:2.2;text-align:center;}
.flow-label .fl-node{color:var(--accent);} .flow-label .fl-arrow{opacity:.35;}
.arch-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:2px;background:var(--border);margin-bottom:2px;}
.arch-card{background:var(--panel);padding:28px;position:relative;overflow:hidden;transition:.3s;cursor:default;}
.arch-card:hover{background:var(--panel2);transform:scale(1.015);z-index:2;}
.arch-num{font-family:'Orbitron',monospace;font-size:3.5rem;font-weight:900;color:rgba(0,212,255,.05);position:absolute;bottom:8px;right:14px;line-height:1;pointer-events:none;}
.arch-badge{font-family:'Share Tech Mono',monospace;font-size:.58rem;color:var(--accent);letter-spacing:3px;margin-bottom:10px;display:block;}
.arch-card h3{font-family:'Orbitron',monospace;font-size:.78rem;letter-spacing:1px;color:var(--text);margin-bottom:12px;}
.arch-card p{font-size:.87rem;color:var(--dim);line-height:1.7;}
.tech-panel{background:var(--panel);padding:30px;margin-bottom:2px;}
.tech-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-top:20px;}
.tech-card{background:var(--bg2);border:1px solid var(--border);padding:18px;text-align:center;transition:.3s;}
.tech-card:hover{border-color:var(--accent);background:rgba(0,212,255,.04);}
.tech-icon{font-size:1.6rem;margin-bottom:10px;display:block;}
.tech-name{font-family:'Orbitron',monospace;font-size:.62rem;color:var(--accent);letter-spacing:2px;margin-bottom:6px;}
.tech-desc{font-family:'Share Tech Mono',monospace;font-size:.68rem;color:var(--dim);}
.toast-wrap{position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px;}
.toast{font-family:'Share Tech Mono',monospace;font-size:.72rem;padding:12px 20px;border:1px solid;background:var(--panel);backdrop-filter:blur(10px);animation:toastIn .35s ease forwards;min-width:260px;}
.toast.success{color:var(--accent2);border-color:var(--accent2);}
.toast.error{color:var(--accent3);border-color:var(--accent3);}
.toast.info{color:var(--accent);border-color:var(--accent);}
@keyframes toastIn{from{opacity:0;transform:translateX(30px)}to{opacity:1;transform:translateX(0)}}
.live-traffic{background:var(--panel);border:1px solid var(--border);padding:20px 24px;margin-bottom:2px;}
.lt-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;}
.lt-title{font-family:'Orbitron',monospace;font-size:.65rem;color:var(--dim);letter-spacing:2px;}
.lt-live{font-family:'Share Tech Mono',monospace;font-size:.6rem;color:var(--accent3);display:flex;align-items:center;gap:5px;}
.lt-dot{width:6px;height:6px;background:var(--accent3);border-radius:50%;animation:blink 1s infinite;}
.err-banner{background:rgba(255,60,110,.08);border:1px solid var(--accent3);color:var(--accent3);font-family:'Share Tech Mono',monospace;font-size:.72rem;padding:12px 16px;margin-bottom:16px;display:flex;align-items:center;gap:8px;}
@media(max-width:900px){
  .pred-layout,.kpi-grid,.charts-grid,.arch-grid{grid-template-columns:1fr;}
  .form-grid{grid-template-columns:1fr;}
  .meta-grid{grid-template-columns:1fr 1fr;}
  .nav{padding:0 16px;}.nav-links{gap:0;}
  .nav-link{padding:6px 10px;font-size:.62rem;}
  .kpi-grid{grid-template-columns:1fr 1fr;}
  .tech-grid{grid-template-columns:1fr 1fr;}
  .dash-layout,.about-layout{padding:16px;}
  .pred-layout{padding:16px;}
  .stats-strip{gap:28px;}
  .hero-title{font-size:1.8rem;}
  .radar-chart{grid-column:auto;}
}
`;

// ─── CUSTOM TOOLTIP ───────────────────────────────────────────────────────────
const CyberTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background:"#071828",border:"1px solid #0e3a5c",padding:"10px 14px",fontFamily:"'Share Tech Mono',monospace",fontSize:".7rem",color:"#c8e6f0" }}>
      <div style={{ color:"#00d4ff",marginBottom:6,letterSpacing:"1px" }}>{label}</div>
      {payload.map((p, i) => <div key={i} style={{ color:p.color }}>{p.name}: {p.value}</div>)}
    </div>
  );
};

// ─── HOOKS ────────────────────────────────────────────────────────────────────
function useCounter(target, duration = 1600) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    let start = null;
    const step = ts => {
      if (!start) start = ts;
      const prog = Math.min((ts - start) / duration, 1);
      setVal(Math.round(prog * target));
      if (prog < 1) requestAnimationFrame(step);
    };
    const id = requestAnimationFrame(step);
    return () => cancelAnimationFrame(id);
  }, [target, duration]);
  return val;
}

function useLiveTraffic() {
  const [data, setData] = useState(() =>
    Array.from({ length: 20 }, (_, i) => ({ t: i, v: Math.round(50 + Math.random() * 80) }))
  );
  useEffect(() => {
    const id = setInterval(() => {
      setData(prev => [...prev.slice(1), { t: prev[prev.length-1].t+1, v: Math.round(40 + Math.random()*200) }]);
    }, 1200);
    return () => clearInterval(id);
  }, []);
  return data;
}

function useToast() {
  const [toasts, setToasts] = useState([]);
  const add = useCallback((msg, type = "info") => {
    const id = Date.now();
    setToasts(p => [...p, { id, msg, type }]);
    setTimeout(() => setToasts(p => p.filter(t => t.id !== id)), 3500);
  }, []);
  return { toasts, add };
}

// ─── COMPONENTS ───────────────────────────────────────────────────────────────
function ToastContainer({ toasts }) {
  return (
    <div className="toast-wrap">
      {toasts.map(t => <div key={t.id} className={`toast ${t.type}`}>{t.msg}</div>)}
    </div>
  );
}

function Navbar({ page, setPage }) {
  const links = [
    { id:"home", label:"HOME" }, { id:"predict", label:"PREDICT" },
    { id:"dashboard", label:"DASHBOARD" }, { id:"about", label:"ABOUT" },
  ];
  return (
    <nav className="nav">
      <div className="nav-brand"><div className="nav-hex">🛡</div>CAPS SYSTEM</div>
      <div className="nav-links">
        {links.map(l => (
          <button key={l.id} className={`nav-link ${page===l.id?"active":""}`} onClick={() => setPage(l.id)}>{l.label}</button>
        ))}
      </div>
      <div className="nav-right">
        <div className="threat-badge">⚠ THREAT: ELEVATED</div>
        <div className="status-pill"><div className="status-dot"/>ONLINE</div>
      </div>
    </nav>
  );
}

function Ticker() {
  const msg = "⚡ ML MODEL LOADED — RANDOM FOREST v2.4 ● ACCURACY: 96.4% ● MONITORING: 4 NODES SECURED ● LAST SCAN: 0:00:12 AGO ● LOGS STORED: 12,483 ● DDoS SIGNATURES: UPDATED ● PHISHING DB: CURRENT ● FIREWALL: ACTIVE ● IDS: RUNNING ●";
  return (
    <div className="ticker">
      <div className="ticker-track">
        <span className="ticker-alert">⚠</span>{msg}<span className="ticker-ok">✓</span>{msg}
      </div>
    </div>
  );
}

// ─── HOME PAGE ────────────────────────────────────────────────────────────────
function HomePage({ setPage }) {
  const acc = useCounter(96);
  const att = useCounter(4);
  const feat = useCounter(6);
  const prec = useCounter(12);
  const threats = [
    { icon:"🎣", name:"PHISHING",    color:"#ff3c6e", desc:"Detects suspicious URLs, abnormal link lengths, and deceptive email patterns.", tags:["URL Analysis","Email Forensics"] },
    { icon:"💥", name:"DDoS",        color:"#ff6b35", desc:"Identifies distributed denial-of-service from abnormal traffic volume spikes.", tags:["Traffic Monitor","Rate Limit"] },
    { icon:"🦠", name:"MALWARE",     color:"#a855f7", desc:"Detects malicious software behavior through file activity and network patterns.", tags:["File Analysis","Heuristics"] },
    { icon:"🔐", name:"BRUTE FORCE", color:"#ffaa00", desc:"Flags repeated failed login attempts and credential stuffing attacks.", tags:["Login Monitor","IP Block"] },
  ];
  return (
    <div className="page-root">
      <div className="hero">
        {[500,700,900].map((s,i) => (
          <div key={i} className="hero-orbit" style={{ width:s,height:s,borderColor:`rgba(0,212,255,${0.06-i*0.015})`,animation:`gridMove ${25+i*15}s linear infinite`,top:"50%",left:"50%",transform:"translate(-50%,-50%)" }}/>
        ))}
        <div className="hero-content" style={{ position:"relative",zIndex:2 }}>
          <div className="hero-tag">// MACHINE LEARNING CYBERSECURITY PLATFORM v2.4 //</div>
          <h1 className="hero-title">CYBER ATTACKS<br/>PREDICTION &amp;<br/>PRECAUTIONS SYSTEM</h1>
          <p className="hero-sub">Real-time threat detection using Random Forest ML. Classify attacks, assess risk levels, and receive actionable precautions — all in one platform.</p>
          <div className="hero-btns">
            <button className="btn-primary" onClick={() => setPage("predict")}>⚡ START ANALYSIS</button>
            <button className="btn-ghost"   onClick={() => setPage("about")}>◈ ARCHITECTURE</button>
          </div>
        </div>
      </div>
      <div className="stats-strip">
        {[{val:acc,suf:"%",label:"ML ACCURACY RATE"},{val:att,suf:"",label:"ATTACK TYPES DETECTED"},{val:feat,suf:"",label:"FEATURES ANALYZED"},{val:prec,suf:"",label:"PRECAUTION ADVISORIES"}].map((s,i) => (
          <div key={i} style={{ textAlign:"center" }}>
            <span className="stat-num">{s.val}{s.suf}</span>
            <div className="stat-label">{s.label}</div>
          </div>
        ))}
      </div>
      <div className="threat-grid">
        {threats.map(t => (
          <div key={t.name} className="threat-card" style={{ "--tc":t.color }}>
            <span className="threat-icon">{t.icon}</span>
            <h3>{t.name}</h3><p>{t.desc}</p>
            <div className="threat-badge-row">{t.tags.map(tag => <span key={tag} className="tag">{tag}</span>)}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── PREDICT PAGE ─────────────────────────────────────────────────────────────
// ✅ FIX: Single clean component — no duplicate functions, no out-of-scope state
function PredictPage({ logs, setLogs, addToast }) {
  const [form, setForm]       = useState({ ip:"", port:"", proto:"", traffic:100, logins:0, url:50 });
  const [errors, setErrors]   = useState({});
  const [state, setState]     = useState("idle");   // idle | processing | result
  const [procStep, setProcStep] = useState(-1);
  const [result, setResult]   = useState(null);
  const [confWidth, setConfWidth] = useState(0);
  const [apiError, setApiError] = useState("");

  const setField = (k, v) => setForm(p => ({ ...p, [k]: v }));

  const validate = () => {
    const errs = {};
    if (!validateIP(form.ip)) errs.ip = "Enter a valid IP (e.g. 192.168.1.1)";
    if (!form.port || +form.port < 0 || +form.port > 65535) errs.port = "Port must be 0–65535";
    if (!form.proto) errs.proto = "Select a protocol";
    return errs;
  };

  const loadDemo = () => {
    const d = DEMO_SETS[Math.floor(Math.random() * DEMO_SETS.length)];
    setForm({ ip:d.ip, port:d.port, proto:d.proto, traffic:+d.traffic, logins:+d.logins, url:+d.url });
    setErrors({});
    addToast("Demo values loaded", "info");
  };

  // ✅ FIX: Single analyze function — validates, animates, calls API, shows result
  const analyze = async () => {
    const errs = validate();
    if (Object.keys(errs).length) { setErrors(errs); return; }
    setErrors({});
    setApiError("");
    setState("processing");
    setProcStep(0);

    // Animate processing steps
    for (let i = 0; i < PROC_STEPS.length; i++) {
      await new Promise(r => setTimeout(r, 420));
      setProcStep(i + 1);
    }

    try {
      const res = await fetch("http://localhost:5000/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          port:    Number(form.port),
          traffic: Number(form.traffic),
          logins:  Number(form.logins),
          url:     Number(form.url),
          proto:   form.proto,
        }),
      });

      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const data = await res.json();

      // ✅ FIX: Actually set result and transition to result state
      setResult({
        isAttack:   data.isAttack,
        attackType: data.attackType,
        risk:       data.risk,
        conf:       data.confidence,
      });
      setState("result");

      // Animate confidence bar
      setTimeout(() => setConfWidth(data.confidence), 100);

      // ✅ FIX: Append to log history
      const newLog = {
        id:         Date.now(),
        ts:         nowTS(),
        ip:         form.ip,
        port:       form.port,
        proto:      form.proto,
        traffic:    form.traffic,
        logins:     form.logins,
        url:        form.url,
        isAttack:   data.isAttack,
        attackType: data.isAttack ? data.attackType : "N/A",
        risk:       data.risk,
        conf:       data.confidence,
      };
      setLogs(prev => [newLog, ...prev]);
      addToast(data.isAttack ? `⚠ ${data.attackType} detected!` : "✓ Traffic is normal", data.isAttack ? "error" : "success");

    } catch (err) {
      setState("idle");
      setApiError(`Cannot reach backend: ${err.message}. Make sure backend.py is running on port 5000.`);
      addToast("Backend connection failed", "error");
    }
  };

  const reset = () => { setState("idle"); setResult(null); setConfWidth(0); setApiError(""); };

  return (
    <div className="page-root">
      <div className="pred-layout">
        {/* Input Panel */}
        <div className="panel">
          <div className="panel-hdr">
            <div className="panel-icon">📡</div>
            <h2>NETWORK PARAMETERS</h2>
            <span className="sub">RF MODEL ACTIVE</span>
          </div>

          {apiError && <div className="err-banner">⚠ {apiError}</div>}

          <div className="form-grid">
            <div className={`field ${errors.ip?"err":""}`}>
              <label>IP ADDRESS <span className="field-hint">IPv4</span></label>
              <input value={form.ip} onChange={e => setField("ip", e.target.value)} placeholder="192.168.1.1"/>
              <div className="field-err">{errors.ip}</div>
            </div>
            <div className={`field ${errors.port?"err":""}`}>
              <label>PORT NUMBER <span className="field-hint">0–65535</span></label>
              <input type="number" value={form.port} onChange={e => setField("port", e.target.value)} placeholder="8080"/>
              <div className="field-err">{errors.port}</div>
            </div>
          </div>

          <div className={`field ${errors.proto?"err":""}`}>
            <label>PROTOCOL TYPE</label>
            <select value={form.proto} onChange={e => setField("proto", e.target.value)}>
              <option value="">— SELECT PROTOCOL —</option>
              {["TCP","UDP","ICMP","HTTP","HTTPS","FTP","SSH","SMTP"].map(p => <option key={p} value={p}>{p}</option>)}
            </select>
            <div className="field-err">{errors.proto}</div>
          </div>

          {[
            { key:"traffic", label:"TRAFFIC VOLUME", hint:"MB/s",  min:0, max:10000, step:50 },
            { key:"logins",  label:"FAILED LOGINS",  hint:"count", min:0, max:100,   step:1  },
            { key:"url",     label:"URL LENGTH",      hint:"chars", min:0, max:500,   step:5  },
          ].map(({ key, label, hint, min, max, step }) => (
            <div className="field" key={key}>
              <label>{label} <span className="field-hint">{hint}</span></label>
              <div className="range-wrap">
                <input type="range" min={min} max={max} step={step} value={form[key]} onChange={e => setField(key, +e.target.value)}/>
                <div className="range-val">{form[key].toLocaleString()}</div>
              </div>
            </div>
          ))}

          <button className="btn-analyze" onClick={analyze} disabled={state==="processing"}>
            {state==="processing" ? "⟳  ANALYZING..." : "⚡  ANALYZE THREAT"}
          </button>
          <button className="btn-demo" onClick={loadDemo}>Load Random Demo Values</button>
        </div>

        {/* Result Panel */}
        <div className="panel">
          <div className="panel-hdr">
            <div className="panel-icon">🎯</div>
            <h2>PREDICTION RESULT</h2>
            {state==="result" && (
              <button onClick={reset} style={{ marginLeft:"auto",background:"none",border:"1px solid #0e3a5c",color:"#5a8a9f",padding:"4px 12px",fontFamily:"'Share Tech Mono',monospace",fontSize:".62rem",cursor:"pointer",letterSpacing:"1px" }}>RESET</button>
            )}
          </div>

          {state==="idle" && (
            <div className="res-idle">
              <div className="res-idle-icon">🛡</div>
              <div>AWAITING INPUT</div>
              <p>Submit network parameters to begin threat analysis</p>
            </div>
          )}

          {state==="processing" && (
            <div className="proc-wrap">
              <div className="proc-ring"/>
              <div className="proc-label">ANALYZING...</div>
              <div className="proc-steps">
                {PROC_STEPS.map((s, i) => (
                  <div key={i} className={`proc-step ${i < procStep?"done":i===procStep?"active":""}`}>
                    <div className="proc-dot"/>{s}
                  </div>
                ))}
              </div>
            </div>
          )}

          {state==="result" && result && (
            <div>
              <div className={`res-verdict ${result.isAttack?"attack":"safe"}`}>
                <div className="verdict-lbl">PREDICTION RESULT</div>
                <div className="verdict-txt">{result.isAttack ? "⚠ ATTACK DETECTED" : "✓ TRAFFIC NORMAL"}</div>
              </div>
              <div className="meta-grid">
                <div className="meta-box">
                  <span className="meta-lbl">ATTACK TYPE</span>
                  <div className="meta-val" style={{ fontSize:".88rem",color:result.isAttack?(ATTACK_COLORS[result.attackType]??"var(--accent3)"):"var(--accent2)" }}>
                    {result.attackType}
                  </div>
                </div>
                <div className="meta-box">
                  <span className="meta-lbl">RISK LEVEL</span>
                  <div className={`meta-val risk-${result.risk}`}>{result.risk}</div>
                </div>
                <div className="meta-box">
                  <span className="meta-lbl">CONFIDENCE</span>
                  <div className="meta-val" style={{ color:"var(--accent)" }}>{result.conf}%</div>
                </div>
              </div>
              <div className="conf-bar-wrap">
                <div className="conf-lbl"><span>CONFIDENCE SCORE</span><span>{result.conf}%</span></div>
                <div className="conf-track"><div className="conf-fill" style={{ width:`${confWidth}%` }}/></div>
              </div>
              <div className="prec-section">
                <h3>{result.isAttack ? "⚠ RECOMMENDED PRECAUTIONS" : "✓ SECURITY STATUS"}</h3>
                {(result.isAttack ? (PRECAUTIONS[result.attackType] ?? []) : ["No immediate action required. Continue monitoring network traffic."]).map((p, i) => (
                  <div key={i} className={`prec-item ${result.isAttack?"":"safe"}`} style={{ animationDelay:`${i*0.1}s` }}>
                    {result.isAttack ? "⚡" : "✓"} {p}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── DASHBOARD PAGE ───────────────────────────────────────────────────────────
function DashboardPage({ logs }) {
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState("ts");
  const [sortDir, setSortDir] = useState("desc");
  const [page, setPage] = useState(0);
  const PER_PAGE = 8;
  const traffic = useLiveTraffic();
  const allLogs = useMemo(() => [...SEED_LOGS, ...logs], [logs]);
  const attacks = allLogs.filter(l => l.isAttack);

  const typeCounts = useMemo(() => {
    const m = { Phishing:0, DDoS:0, Malware:0, "Brute Force":0 };
    attacks.forEach(l => { if (m[l.attackType] !== undefined) m[l.attackType]++; });
    return Object.entries(m).map(([name, value]) => ({ name, value }));
  }, [attacks]);

  const timeData = useMemo(() => {
    const hours = Array.from({ length:8 }, (_, i) => ({ hour:`${7+i}:00`, attacks:0, normal:0 }));
    allLogs.forEach(l => {
      const ts = l.ts?.toString() ?? "";
      const h = parseInt(ts.slice(11,13)) || 8;
      const idx = Math.min(Math.max(h-7,0),7);
      if (l.isAttack) hours[idx].attacks++; else hours[idx].normal++;
    });
    return hours;
  }, [allLogs]);

  const radarData = [
    { subject:"Phishing",    value: typeCounts.find(t=>t.name==="Phishing")?.value ?? 0 },
    { subject:"DDoS",        value: typeCounts.find(t=>t.name==="DDoS")?.value ?? 0 },
    { subject:"Malware",     value: typeCounts.find(t=>t.name==="Malware")?.value ?? 0 },
    { subject:"Brute Force", value: typeCounts.find(t=>t.name==="Brute Force")?.value ?? 0 },
    { subject:"Normal",      value: allLogs.filter(l=>!l.isAttack).length },
  ];

  const sorted = useMemo(() => {
    return [...allLogs]
      .filter(l => !search || l.ip?.includes(search) || l.proto?.toLowerCase().includes(search.toLowerCase()) || l.attackType?.toLowerCase().includes(search.toLowerCase()))
      .sort((a,b) => {
        const av = a[sortKey]??"", bv = b[sortKey]??"";
        return sortDir==="asc" ? (av>bv?1:-1) : (av<bv?1:-1);
      });
  }, [allLogs, search, sortKey, sortDir]);

  const paginated = sorted.slice(page*PER_PAGE, (page+1)*PER_PAGE);
  const totalPages = Math.ceil(sorted.length/PER_PAGE);
  const sort = key => { if (sortKey===key) setSortDir(d=>d==="asc"?"desc":"asc"); else { setSortKey(key); setSortDir("desc"); } };
  const PIE_COLORS = ["#ff3c6e","#ff6b35","#a855f7","#ffaa00"];

  const kpis = [
    { label:"TOTAL SCANS",    val:allLogs.length,                              sub:"all time",          color:"var(--accent)" },
    { label:"ATTACKS FOUND",  val:attacks.length,                              sub:`${Math.round(attacks.length/Math.max(allLogs.length,1)*100)}% of total`, color:"var(--accent3)" },
    { label:"NORMAL TRAFFIC", val:allLogs.length-attacks.length,               sub:"clean sessions",    color:"var(--accent2)" },
    { label:"HIGH RISK",      val:allLogs.filter(l=>l.risk==="HIGH").length,    sub:"critical alerts",   color:"var(--accent4)" },
  ];

  return (
    <div className="page-root">
      <div className="dash-layout">
        <div className="page-title">ANALYTICS DASHBOARD</div>
        <div className="kpi-grid">
          {kpis.map(k => (
            <div key={k.label} className="kpi" style={{ "--kc":k.color }}>
              <div className="kpi-lbl">{k.label}</div>
              <div className="kpi-val">{k.val}</div>
              <div className="kpi-sub">{k.sub}</div>
            </div>
          ))}
        </div>
        <div className="live-traffic">
          <div className="lt-hdr">
            <span className="lt-title">LIVE NETWORK TRAFFIC</span>
            <span className="lt-live"><span className="lt-dot"/> REAL-TIME</span>
          </div>
          <ResponsiveContainer width="100%" height={100}>
            <LineChart data={traffic}>
              <Line type="monotone" dataKey="v" stroke="#00d4ff" strokeWidth={1.5} dot={false} isAnimationActive={false}/>
              <YAxis domain={[0,250]} hide/>
              <Tooltip content={<CyberTooltip/>}/>
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div className="charts-grid">
          <div className="chart-panel">
            <div className="chart-title">ATTACK TYPE DISTRIBUTION</div>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={typeCounts} barSize={28}>
                <CartesianGrid strokeDasharray="2 4" stroke="#0e3a5c"/>
                <XAxis dataKey="name" tick={{ fontFamily:"'Share Tech Mono',monospace",fontSize:10,fill:"#5a8a9f" }}/>
                <YAxis tick={{ fontFamily:"'Share Tech Mono',monospace",fontSize:10,fill:"#5a8a9f" }}/>
                <Tooltip content={<CyberTooltip/>}/>
                <Bar dataKey="value" radius={0}>
                  {typeCounts.map((_,i) => <Cell key={i} fill={PIE_COLORS[i]}/>)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="chart-panel">
            <div className="chart-title">ATTACK TYPE SHARE</div>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={typeCounts} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} innerRadius={40} stroke="none">
                  {typeCounts.map((_,i) => <Cell key={i} fill={PIE_COLORS[i]}/>)}
                </Pie>
                <Tooltip content={<CyberTooltip/>}/>
                <Legend wrapperStyle={{ fontFamily:"'Share Tech Mono',monospace",fontSize:"10px",color:"#5a8a9f" }}/>
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="chart-panel" style={{ gridColumn:"1/-1" }}>
            <div className="chart-title">THREAT TIMELINE (HOURLY)</div>
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={timeData} barSize={16}>
                <CartesianGrid strokeDasharray="2 4" stroke="#0e3a5c"/>
                <XAxis dataKey="hour" tick={{ fontFamily:"'Share Tech Mono',monospace",fontSize:10,fill:"#5a8a9f" }}/>
                <YAxis tick={{ fontFamily:"'Share Tech Mono',monospace",fontSize:10,fill:"#5a8a9f" }}/>
                <Tooltip content={<CyberTooltip/>}/>
                <Legend wrapperStyle={{ fontFamily:"'Share Tech Mono',monospace",fontSize:"10px",color:"#5a8a9f" }}/>
                <Bar dataKey="attacks" name="Attacks" fill="#ff3c6e" radius={0}/>
                <Bar dataKey="normal"  name="Normal"  fill="#00ff9d" radius={0}/>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="chart-panel radar-chart">
            <div className="chart-title">THREAT RADAR</div>
            <ResponsiveContainer width="100%" height={240}>
              <RadarChart data={radarData}>
                <PolarGrid stroke="#0e3a5c"/>
                <PolarAngleAxis dataKey="subject" tick={{ fontFamily:"'Share Tech Mono',monospace",fontSize:10,fill:"#5a8a9f" }}/>
                <Radar name="Threats" dataKey="value" stroke="#00d4ff" fill="#00d4ff" fillOpacity={0.15}/>
                <Tooltip content={<CyberTooltip/>}/>
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="history-panel">
          <div className="hist-hdr">
            <h2>PREDICTION LOG</h2>
            <div className="hist-controls">
              <input className="hist-search" placeholder="Search IP / protocol / type..." value={search} onChange={e => { setSearch(e.target.value); setPage(0); }}/>
              <button className="btn-clear" onClick={() => { if(window.confirm("Clear session logs?")) window.location.reload(); }}>CLEAR</button>
            </div>
          </div>
          <div style={{ overflowX:"auto" }}>
            <table className="hist-table">
              <thead>
                <tr>
                  {[["ts","TIMESTAMP"],["ip","IP ADDRESS"],["proto","PROTOCOL"],["traffic","TRAFFIC"],["logins","LOGINS"],["isAttack","RESULT"],["attackType","TYPE"],["risk","RISK"],["conf","CONF%"]].map(([k,h]) => (
                    <th key={k} onClick={() => sort(k)}>{h} {sortKey===k?(sortDir==="asc"?"↑":"↓"):""}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {paginated.map(l => (
                  <tr key={l.id}>
                    <td style={{ color:"var(--dim)",fontSize:".65rem" }}>{l.ts}</td>
                    <td>{l.ip}</td>
                    <td>{l.proto}</td>
                    <td>{(+l.traffic).toLocaleString()}</td>
                    <td>{l.logins}</td>
                    <td><span className={`badge ${l.isAttack?"b-atk":"b-safe"}`}>{l.isAttack?"ATTACK":"NORMAL"}</span></td>
                    <td style={{ color:l.isAttack?(ATTACK_COLORS[l.attackType]??"var(--accent3)"):"var(--accent2)" }}>{l.attackType}</td>
                    <td><span className={`badge b-${l.risk?.toLowerCase()}`}>{l.risk}</span></td>
                    <td style={{ color:"var(--accent)",fontFamily:"'Orbitron',monospace",fontSize:".75rem" }}>{l.conf}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {paginated.length===0 && <div className="empty-state">NO MATCHING LOGS</div>}
          {totalPages>1 && (
            <div className="pagination">
              <button className="page-btn" onClick={() => setPage(p=>p-1)} disabled={page===0}>‹</button>
              {Array.from({ length:totalPages },(_,i) => (
                <button key={i} className={`page-btn ${page===i?"active":""}`} onClick={() => setPage(i)}>{i+1}</button>
              ))}
              <button className="page-btn" onClick={() => setPage(p=>p+1)} disabled={page>=totalPages-1}>›</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── ABOUT PAGE ───────────────────────────────────────────────────────────────
function AboutPage() {
  const steps = [
    { n:"01", badge:"DATA COLLECTION",     title:"Data Collection Layer",      body:"Collects network traffic data (IP, port, protocol, volume), user activity logs, login attempts, URL attributes for phishing detection, and file behavior data for malware detection." },
    { n:"02", badge:"DATA PREPROCESSING",  title:"Data Preprocessing",         body:"Cleans data by removing null values and duplicates. Encodes categorical variables. Applies normalization and Min-Max scaling. Splits dataset 70/30 train/test." },
    { n:"03", badge:"FEATURE ENGINEERING", title:"Feature Engineering",        body:"Selects key features using correlation analysis and feature importance scoring. Extracts failed logins, traffic rate, suspicious ports, and URL anomalies." },
    { n:"04", badge:"ML MODEL TRAINING",   title:"ML Model Training",          body:"Trains using Logistic Regression, Decision Tree, Random Forest, and SVM. Random Forest selected as primary model with 96.4% accuracy on test data." },
    { n:"05", badge:"MODEL EVALUATION",    title:"Model Evaluation",           body:"Evaluates using Accuracy, Precision, Recall, and F1-Score metrics. Confusion matrix analysis performed. Model retrained until performance thresholds are met." },
    { n:"06", badge:"MODEL DEPLOYMENT",    title:"Model Deployment",           body:"Saves trained model as Pickle/Joblib file. Integrates with Flask backend server. Prepares REST API endpoints for real-time prediction requests from the frontend." },
    { n:"07", badge:"REAL-TIME PREDICTION",title:"Real-Time Prediction",       body:"Receives user input from web interface, applies the same preprocessing pipeline, feeds data into ML model, generates prediction with confidence score." },
    { n:"08", badge:"ATTACK CLASSIFICATION",title:"Attack Classification",     body:"Classifies detected attack as Phishing, DDoS, Malware, or Brute Force. Provides specific precaution recommendations for each detected attack type." },
    { n:"09", badge:"RESULT LOGGING",      title:"Result Logging & Dashboard", body:"Stores all prediction results in SQLite database. Maintains history logs for analytics. Generates statistical charts and live threat dashboard." },
  ];
  const tech = [
    { icon:"⚛", name:"REACT",         desc:"Dynamic UI components, hooks, state management" },
    { icon:"🎨", name:"CSS3",          desc:"Custom animations, CSS variables, grid & flex" },
    { icon:"📊", name:"RECHARTS",      desc:"BarChart, LineChart, PieChart, RadarChart" },
    { icon:"🐍", name:"PYTHON FLASK",  desc:"Backend API, route handling, ML integration" },
    { icon:"🤖", name:"SCIKIT-LEARN",  desc:"Random Forest, preprocessing, joblib model" },
    { icon:"🗄", name:"SQLITE",        desc:"Prediction log storage, history queries" },
    { icon:"🐼", name:"PANDAS",        desc:"Data cleaning, feature engineering, CSV I/O" },
    { icon:"🔢", name:"NUMPY",         desc:"Numerical computation, array operations" },
  ];
  const flowNodes = ["USER","FRONTEND","BACKEND","PREPROCESSING","ML MODEL","CLASSIFICATION","PRECAUTION ENGINE","DATABASE","RESPONSE"];
  return (
    <div className="page-root">
      <div className="about-layout">
        <div className="about-hero">
          <div style={{ fontFamily:"'Share Tech Mono',monospace",fontSize:".68rem",color:"var(--accent2)",letterSpacing:"5px",marginBottom:"14px" }}>// SYSTEM ARCHITECTURE //</div>
          <h1 style={{ fontFamily:"'Orbitron',monospace",fontSize:"1.8rem",color:"var(--accent)",textShadow:"var(--glow)",letterSpacing:"4px",marginBottom:"20px" }}>PROCESS ARCHITECTURE</h1>
        </div>
        <div className="flow-label">
          {flowNodes.map((n,i) => (
            <span key={n}><span className="fl-node">{n}</span>{i<flowNodes.length-1&&<span className="fl-arrow"> → </span>}</span>
          ))}
        </div>
        <div className="arch-grid">
          {steps.map(s => (
            <div key={s.n} className="arch-card">
              <div className="arch-num">{s.n}</div>
              <span className="arch-badge">// {s.badge}</span>
              <h3>{s.title}</h3><p>{s.body}</p>
            </div>
          ))}
        </div>
        <div className="tech-panel">
          <div style={{ fontFamily:"'Orbitron',monospace",fontSize:".8rem",color:"var(--accent)",letterSpacing:"3px" }}>TECHNOLOGY STACK</div>
          <div className="tech-grid">
            {tech.map(t => (
              <div key={t.name} className="tech-card">
                <span className="tech-icon">{t.icon}</span>
                <div className="tech-name">{t.name}</div>
                <div className="tech-desc">{t.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── APP ──────────────────────────────────────────────────────────────────────
export default function App() {
  const [page, setPage]   = useState("home");
  const [logs, setLogs]   = useState([]);
  const { toasts, add: addToast } = useToast();
  return (
    <>
      <style>{css}</style>
      <Navbar page={page} setPage={setPage}/>
      <Ticker/>
      {page==="home"      && <HomePage setPage={setPage}/>}
      {page==="predict"   && <PredictPage logs={logs} setLogs={setLogs} addToast={addToast}/>}
      {page==="dashboard" && <DashboardPage logs={logs}/>}
      {page==="about"     && <AboutPage/>}
      <ToastContainer toasts={toasts}/>
    </>
  );
}
