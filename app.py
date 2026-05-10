#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║           CROW-LINK Security Platform v2.0                ║
║   45-Tool Professional Security Framework (Single File)   ║
╚═══════════════════════════════════════════════════════════╝
Usage:
    pip install flask requests python-whois dnspython Pillow qrcode reportlab
    python standalone_app.py
Login: zrougtaib@gmail.com / #FFHUDT6O3jqu9cSBPo7eO
"""

import os, json, hashlib, base64, socket, ssl, subprocess
import urllib.parse, struct, re, time, threading
from datetime import datetime
from io import BytesIO
from functools import wraps
from flask import Flask, request, session, redirect, url_for, jsonify, send_file
from jinja2 import DictLoader

# ── Optional imports ──────────────────────────────────────
try:
    import whois as whois_lib; WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
try:
    import dns.resolver, dns.reversename; DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
try:
    from PIL import Image; from PIL.ExifTags import TAGS; PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
try:
    import qrcode as qrcode_lib; QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False
try:
    from reportlab.pdfgen import canvas as pdf_canvas
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ═══════════════════════════════════════════════════════════
#  TEMPLATES
# ═══════════════════════════════════════════════════════════

BASE_HTML = r"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{% block title %}CROW-LINK Security{% endblock %}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@300;400;600;700;900&family=Fira+Code:wght@300;400;500;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{--gold:#FFD700;--gold-dim:#c9a900;--gold-glow:rgba(255,215,0,.15);--bg-primary:#0a0a0f;--bg-secondary:#0f0f1a;--bg-card:#111122;--bg-sidebar:#09090f;--border:rgba(255,215,0,.15);--border-bright:rgba(255,215,0,.4);--text-primary:#e8e8f0;--text-muted:#6a6a8a;--danger:#ff4757;--success:#2ed573;--warning:#ffa502;--sidebar-w:270px}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Cairo',sans-serif;background:var(--bg-primary);color:var(--text-primary);direction:rtl;overflow-x:hidden;min-height:100vh}
#matrix-canvas{position:fixed;top:0;left:0;width:100%;height:100%;z-index:0;pointer-events:none;opacity:.04}
.app-layout{display:flex;min-height:100vh;position:relative;z-index:1}
.sidebar{width:var(--sidebar-w);background:var(--bg-sidebar);border-left:1px solid var(--border);display:flex;flex-direction:column;position:fixed;top:0;right:0;height:100vh;overflow-y:auto;overflow-x:hidden;z-index:100}
.sidebar::-webkit-scrollbar{width:4px}.sidebar::-webkit-scrollbar-thumb{background:var(--border-bright);border-radius:2px}
.sidebar-logo{padding:24px 20px 16px;border-bottom:1px solid var(--border);text-align:center}
.sidebar-logo .logo-icon{font-size:2.5rem;display:block;margin-bottom:6px;filter:drop-shadow(0 0 12px var(--gold))}
.sidebar-logo h1{font-size:1rem;font-weight:900;color:var(--gold);letter-spacing:2px;text-shadow:0 0 20px rgba(255,215,0,.4);font-family:'Fira Code',monospace}
.sidebar-logo span{font-size:.65rem;color:var(--text-muted);font-family:'Fira Code',monospace;letter-spacing:1px}
.sidebar-nav{padding:12px 0;flex:1}
.nav-section{margin-bottom:4px}
.nav-section-header{padding:8px 20px 4px;font-size:.62rem;font-family:'Fira Code',monospace;color:var(--gold);letter-spacing:2px;text-transform:uppercase;opacity:.8;display:flex;align-items:center;gap:8px}
.nav-section-header::before{content:'';flex:1;height:1px;background:var(--border)}
.nav-item{display:flex;align-items:center;gap:10px;padding:8px 20px;color:var(--text-muted);text-decoration:none;font-size:.8rem;transition:all .2s;border-right:3px solid transparent}
.nav-item:hover,.nav-item.active{color:var(--text-primary);background:linear-gradient(90deg,transparent,var(--gold-glow));border-right-color:var(--gold)}
.nav-item.active{color:var(--gold)}
.nav-item .nav-icon{width:18px;text-align:center;font-size:.75rem;flex-shrink:0}
.sidebar-footer{padding:16px 20px;border-top:1px solid var(--border)}
.user-info{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.user-avatar{width:32px;height:32px;background:linear-gradient(135deg,var(--gold),var(--gold-dim));border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.8rem;color:#000;font-weight:700;flex-shrink:0}
.user-email{font-size:.7rem;color:var(--text-muted);font-family:'Fira Code',monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.btn-logout{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;padding:9px;background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.3);color:#ff4757;border-radius:8px;font-size:.8rem;font-family:'Cairo',sans-serif;cursor:pointer;transition:all .2s;text-decoration:none}
.btn-logout:hover{background:rgba(255,71,87,.2);border-color:#ff4757}
.main-content{margin-right:var(--sidebar-w);flex:1;padding:28px 32px;min-height:100vh}
.page-header{display:flex;align-items:center;gap:16px;margin-bottom:28px;padding-bottom:20px;border-bottom:1px solid var(--border)}
.page-header .header-icon{width:50px;height:50px;background:linear-gradient(135deg,var(--gold-glow),rgba(255,215,0,.05));border:1px solid var(--border-bright);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.4rem;flex-shrink:0}
.page-header h2{font-size:1.5rem;font-weight:700;color:var(--gold);text-shadow:0 0 20px rgba(255,215,0,.3)}
.page-header p{font-size:.8rem;color:var(--text-muted);margin-top:2px}
.unit-badge{margin-right:auto;padding:4px 12px;background:var(--gold-glow);border:1px solid var(--border-bright);border-radius:20px;font-size:.65rem;font-family:'Fira Code',monospace;color:var(--gold);letter-spacing:1px}
.card{background:var(--bg-card);border:1px solid var(--border);border-radius:14px;padding:24px;margin-bottom:20px;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;right:0;width:100%;height:2px;background:linear-gradient(90deg,transparent,var(--gold),transparent);opacity:.4}
.form-group{margin-bottom:18px}
.form-label{display:block;margin-bottom:8px;font-size:.85rem;font-weight:600;color:var(--text-primary)}
.form-control{width:100%;padding:11px 14px;background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:8px;color:var(--text-primary);font-family:'Fira Code',monospace;font-size:.85rem;direction:ltr;transition:border-color .2s,box-shadow .2s;outline:none}
.form-control:focus{border-color:var(--gold);box-shadow:0 0 0 3px rgba(255,215,0,.08);background:rgba(255,215,0,.03)}
.form-control::placeholder{color:var(--text-muted)}
textarea.form-control{min-height:120px;resize:vertical}
select.form-control{cursor:pointer;direction:rtl}
.btn{display:inline-flex;align-items:center;gap:8px;padding:11px 24px;border:none;border-radius:8px;font-size:.9rem;font-family:'Cairo',sans-serif;font-weight:600;cursor:pointer;transition:all .2s;text-decoration:none}
.btn-primary{background:linear-gradient(135deg,var(--gold),var(--gold-dim));color:#000}
.btn-primary:hover{transform:translateY(-1px);box-shadow:0 4px 20px rgba(255,215,0,.3)}
.btn-secondary{background:rgba(255,255,255,.06);border:1px solid var(--border);color:var(--text-primary)}
.btn-secondary:hover{border-color:var(--gold);color:var(--gold)}
.btn-danger{background:rgba(255,71,87,.15);border:1px solid rgba(255,71,87,.4);color:#ff4757}
.result-box{background:rgba(0,0,0,.4);border:1px solid var(--border);border-radius:10px;padding:20px;margin-top:20px;position:relative}
.result-box.success{border-color:rgba(46,213,115,.3)}.result-box.error{border-color:rgba(255,71,87,.3)}
.result-header{display:flex;align-items:center;gap:10px;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.result-status{font-size:.75rem;font-family:'Fira Code',monospace;letter-spacing:1px}
.result-status.ok{color:var(--success)}.result-status.err{color:var(--danger)}
.result-data{font-family:'Fira Code',monospace;font-size:.78rem;line-height:1.7;color:#c0c0d0;white-space:pre-wrap;word-break:break-all;max-height:500px;overflow-y:auto;direction:ltr;text-align:left}
.result-data::-webkit-scrollbar{width:4px}.result-data::-webkit-scrollbar-thumb{background:var(--border-bright)}
.alert{padding:12px 16px;border-radius:8px;font-size:.85rem;margin-bottom:16px;display:flex;align-items:center;gap:10px}
.alert-danger{background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.3);color:#ff6b7a}
.status-dot{width:8px;height:8px;border-radius:50%;display:inline-block;animation:pulse 2s infinite}
.status-dot.green{background:var(--success);box-shadow:0 0 6px var(--success)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.sidebar-toggle{display:none;position:fixed;top:16px;left:16px;z-index:200;background:var(--bg-card);border:1px solid var(--border);border-radius:8px;width:40px;height:40px;align-items:center;justify-content:center;cursor:pointer;color:var(--gold);font-size:1.1rem}
@media(max-width:900px){.sidebar{transform:translateX(100%)}.sidebar.open{transform:translateX(0)}.main-content{margin-right:0;padding:16px}.sidebar-toggle{display:flex}}
::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-thumb{background:var(--border-bright);border-radius:3px}
.spinner{width:20px;height:20px;border:2px solid rgba(255,215,0,.2);border-top-color:var(--gold);border-radius:50%;animation:spin .8s linear infinite;display:inline-block}
@keyframes spin{to{transform:rotate(360deg)}}
.qr-output{text-align:center;margin-top:16px}
.qr-output img{border:2px solid var(--border);border-radius:8px;max-width:250px}
.copy-btn{padding:4px 10px;background:rgba(255,215,0,.1);border:1px solid var(--border-bright);border-radius:5px;color:var(--gold);font-size:.7rem;font-family:'Fira Code',monospace;cursor:pointer;transition:all .2s}
.copy-btn:hover{background:rgba(255,215,0,.2)}
{% block extra_css %}{% endblock %}
</style>
</head>
<body>
<canvas id="matrix-canvas"></canvas>
<button class="sidebar-toggle" onclick="document.getElementById('sidebar').classList.toggle('open')">
  <i class="fas fa-bars"></i>
</button>
<div class="app-layout">
 <nav class="sidebar" id="sidebar">
  <div class="sidebar-logo">
   <span class="logo-icon">🦅</span>
   <h1>CROW-LINK</h1>
   <span>SECURITY PLATFORM v2.0</span>
  </div>
  <div class="sidebar-nav">
   <div class="nav-section">
    <div class="nav-section-header"><span>🏠</span> الرئيسية</div>
    <a href="/dashboard" class="nav-item {% if request.path=='/dashboard' %}active{% endif %}">
     <span class="nav-icon"><i class="fas fa-th-large"></i></span><span>لوحة التحكم</span></a>
   </div>
   <div class="nav-section">
    <div class="nav-section-header"><span>🔍</span> RECON UNIT</div>
    {% for path,icon,label in [('/tools/whois','fa-globe','WHOIS Lookup'),('/tools/dns','fa-server','DNS Records'),('/tools/rdns','fa-arrows-rotate','Reverse DNS'),('/tools/subdomain','fa-sitemap','Subdomain Finder'),('/tools/port-tcp','fa-plug','TCP Port Scanner'),('/tools/port-udp','fa-broadcast-tower','UDP Port Scanner'),('/tools/http-headers','fa-code','HTTP Headers'),('/tools/ssl','fa-lock','SSL Inspector'),('/tools/robots','fa-robot','robots.txt Scanner')] %}
    <a href="{{path}}" class="nav-item {{'active' if request.path==path else ''}}">
     <span class="nav-icon"><i class="fas {{icon}}"></i></span><span>{{label}}</span></a>
    {% endfor %}
   </div>
   <div class="nav-section">
    <div class="nav-section-header"><span>🧪</span> LAB UNIT</div>
    {% for path,icon,label in [('/tools/hash-gen','fa-hashtag','Hash Generator'),('/tools/hash-crack','fa-hammer','Hash Cracker'),('/tools/exif','fa-image','EXIF Extractor'),('/tools/base64','fa-code','Base64'),('/tools/url-encode','fa-link','URL Encode/Decode'),('/tools/hex-dump','fa-terminal','Hex Dump'),('/tools/strings','fa-align-left','String Extractor'),('/tools/stego','fa-eye-slash','Stego Detector'),('/tools/qr','fa-qrcode','QR Generator')] %}
    <a href="{{path}}" class="nav-item {{'active' if request.path==path else ''}}">
     <span class="nav-icon"><i class="fas {{icon}}"></i></span><span>{{label}}</span></a>
    {% endfor %}
   </div>
   <div class="nav-section">
    <div class="nav-section-header"><span>🌐</span> WEB ARSENAL</div>
    {% for path,icon,label in [('/tools/sqli','fa-database','SQLi Scanner'),('/tools/xss','fa-code','XSS Tester'),('/tools/csrf','fa-shield-halved','CSRF Tester'),('/tools/dirbust','fa-folder-open','Dir Brute Force'),('/tools/admin-finder','fa-user-shield','Admin Finder'),('/tools/cookies','fa-cookie','Cookie Analyzer'),('/tools/open-redirect','fa-arrow-right-from-bracket','Open Redirect'),('/tools/lfi','fa-file-code','LFI Tester'),('/tools/wordpress','fa-wordpress','WordPress Scanner')] %}
    <a href="{{path}}" class="nav-item {{'active' if request.path==path else ''}}">
     <span class="nav-icon"><i class="fas {{icon}}"></i></span><span>{{label}}</span></a>
    {% endfor %}
   </div>
   <div class="nav-section">
    <div class="nav-section-header"><span>🛡️</span> NETWORK WARFARE</div>
    {% for path,icon,label in [('/tools/packet-sniffer','fa-wave-square','Packet Sniffer'),('/tools/proxy-checker','fa-filter','Proxy Checker'),('/tools/wol','fa-power-off','Wake-on-LAN'),('/tools/ping-sweep','fa-satellite-dish','Ping Sweeper'),('/tools/traceroute','fa-route','Traceroute'),('/tools/arp','fa-table-list','ARP Table'),('/tools/speed-test','fa-gauge-high','Speed Test'),('/tools/firewall-test','fa-fire','Firewall Tester'),('/tools/vpn-detect','fa-mask','VPN Detector')] %}
    <a href="{{path}}" class="nav-item {{'active' if request.path==path else ''}}">
     <span class="nav-icon"><i class="fas {{icon}}"></i></span><span>{{label}}</span></a>
    {% endfor %}
   </div>
   <div class="nav-section">
    <div class="nav-section-header"><span>🖥️</span> COMMAND ROOM</div>
    {% for path,icon,label in [('/tools/gps-tracker','fa-map-location-dot','GPS Tracker'),('/tools/remote-console','fa-terminal','Remote Console'),('/tools/report-gen','fa-file-pdf','Report Generator'),('/tools/ip-geo','fa-earth-africa','IP Geolocation'),('/tools/email-breach','fa-envelope-open-text','Email Breach'),('/tools/mac-lookup','fa-network-wired','MAC Lookup'),('/tools/phishing','fa-fish','Phishing Detector'),('/tools/malware-hash','fa-biohazard','Malware Hash'),('/tools/threat-map','fa-map','Live Threat Map')] %}
    <a href="{{path}}" class="nav-item {{'active' if request.path==path else ''}}">
     <span class="nav-icon"><i class="fas {{icon}}"></i></span><span>{{label}}</span></a>
    {% endfor %}
   </div>
  </div>
  <div class="sidebar-footer">
   <div class="user-info">
    <div class="user-avatar">Z</div>
    <div class="user-email">{{ session.get('user_email','operator') }}</div>
   </div>
   <div style="display:flex;align-items:center;gap:6px;margin-bottom:10px;">
    <span class="status-dot green"></span>
    <span style="font-size:.7rem;color:var(--text-muted);font-family:'Fira Code',monospace;">SYSTEM ONLINE</span>
   </div>
   <a href="/logout" class="btn-logout"><i class="fas fa-right-from-bracket"></i> تسجيل الخروج</a>
  </div>
 </nav>
 <main class="main-content">{% block content %}{% endblock %}</main>
</div>
<script>
const canvas=document.getElementById('matrix-canvas'),ctx=canvas.getContext('2d');
canvas.width=window.innerWidth;canvas.height=window.innerHeight;
const chars='CROW-LINK|01アイウエオカキクケコ|ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%';
const fs=13;let cols=Math.floor(canvas.width/fs),drops=Array(cols).fill(1);
function dm(){ctx.fillStyle='rgba(10,10,15,.05)';ctx.fillRect(0,0,canvas.width,canvas.height);ctx.fillStyle='#FFD700';ctx.font=fs+'px "Fira Code",monospace';for(let i=0;i<drops.length;i++){ctx.fillText(chars[Math.floor(Math.random()*chars.length)],i*fs,drops[i]*fs);if(drops[i]*fs>canvas.height&&Math.random()>.975)drops[i]=0;drops[i]++;}}
setInterval(dm,60);
window.addEventListener('resize',()=>{canvas.width=window.innerWidth;canvas.height=window.innerHeight;cols=Math.floor(canvas.width/fs);drops=Array(cols).fill(1);});
function copyResult(){const d=document.querySelector('.result-data');if(d){navigator.clipboard.writeText(d.textContent).then(()=>{const b=document.querySelector('.copy-btn');if(b){b.textContent='✓ تم النسخ';setTimeout(()=>b.textContent='⎘ نسخ',2000);}});}}
document.addEventListener('DOMContentLoaded',()=>{document.querySelectorAll('form').forEach(f=>{f.addEventListener('submit',e=>{const b=f.querySelector('button[type="submit"]');if(b){b.disabled=true;b.innerHTML='<span class="spinner"></span> جارٍ التنفيذ...';}});});});
</script>
{% block extra_js %}{% endblock %}
</body>
</html>"""

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>CROW-LINK — Login</title>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;700;900&family=Fira+Code:wght@400;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Cairo',sans-serif;background:#0a0a0f;color:#e8e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center;direction:rtl;overflow:hidden}
canvas{position:fixed;top:0;left:0;width:100%;height:100%;z-index:0;pointer-events:none;opacity:.06}
.login-container{position:relative;z-index:10;width:420px;max-width:95vw}
.login-card{background:rgba(15,15,26,.95);border:1px solid rgba(255,215,0,.2);border-radius:20px;padding:40px 36px;box-shadow:0 0 60px rgba(255,215,0,.06),0 0 100px rgba(0,0,0,.5);backdrop-filter:blur(10px);position:relative}
.login-header{text-align:center;margin-bottom:36px}
.login-logo{font-size:3.5rem;display:block;margin-bottom:12px;filter:drop-shadow(0 0 20px rgba(255,215,0,.6));animation:floatLogo 3s ease-in-out infinite}
@keyframes floatLogo{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
.login-title{font-size:1.6rem;font-weight:900;color:#FFD700;letter-spacing:3px;font-family:'Fira Code',monospace;text-shadow:0 0 30px rgba(255,215,0,.4)}
.login-subtitle{font-size:.7rem;color:#5a5a7a;letter-spacing:2px;font-family:'Fira Code',monospace;margin-top:6px}
.divider{height:1px;background:linear-gradient(90deg,transparent,rgba(255,215,0,.3),transparent);margin:20px 0}
.form-group{margin-bottom:20px}
.form-label{display:block;font-size:.82rem;font-weight:600;color:#9090b0;margin-bottom:8px}
.input-wrapper{position:relative}
.input-icon{position:absolute;right:14px;top:50%;transform:translateY(-50%);color:#4a4a6a;font-size:.9rem;transition:color .2s}
.form-control{width:100%;padding:13px 42px 13px 14px;background:rgba(255,255,255,.04);border:1px solid rgba(255,215,0,.12);border-radius:10px;color:#e8e8f0;font-family:'Fira Code',monospace;font-size:.88rem;direction:ltr;text-align:left;outline:none;transition:all .3s}
.form-control:focus{border-color:#FFD700;box-shadow:0 0 0 3px rgba(255,215,0,.08);background:rgba(255,215,0,.02)}
.form-control:focus+.input-icon{color:#FFD700}
.form-control::placeholder{color:#3a3a5a}
.btn-login{width:100%;padding:14px;background:linear-gradient(135deg,#FFD700,#c9a900);border:none;border-radius:10px;color:#000;font-size:1rem;font-weight:700;font-family:'Cairo',sans-serif;cursor:pointer;letter-spacing:1px;transition:all .3s;margin-top:8px}
.btn-login:hover{transform:translateY(-2px);box-shadow:0 6px 30px rgba(255,215,0,.35)}
.alert-error{background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.3);border-radius:8px;padding:12px 16px;font-size:.82rem;color:#ff7b87;margin-bottom:20px;display:flex;align-items:center;gap:10px}
.login-footer{text-align:center;margin-top:24px}
.footer-text{font-size:.65rem;color:#3a3a5a;font-family:'Fira Code',monospace;letter-spacing:1px}
.footer-text span{color:#FFD700}
.scan-line{position:fixed;top:0;left:0;width:100%;height:2px;background:linear-gradient(90deg,transparent,#FFD700,transparent);animation:scanDown 4s linear infinite;opacity:.3;z-index:5}
@keyframes scanDown{0%{top:0}100%{top:100vh}}
.corner{position:absolute;width:20px;height:20px;border-color:rgba(255,215,0,.3);border-style:solid}
.c-tl{top:-1px;right:-1px;border-width:2px 0 0 2px;border-radius:20px 0 0 0}
.c-tr{top:-1px;left:-1px;border-width:2px 2px 0 0;border-radius:0 20px 0 0}
.c-bl{bottom:-1px;right:-1px;border-width:0 0 2px 2px;border-radius:0 0 0 20px}
.c-br{bottom:-1px;left:-1px;border-width:0 2px 2px 0;border-radius:0 0 20px 0}
</style>
</head>
<body>
<canvas id="m"></canvas><div class="scan-line"></div>
<div class="login-container">
 <div class="login-card">
  <div class="corner c-tl"></div><div class="corner c-tr"></div>
  <div class="corner c-bl"></div><div class="corner c-br"></div>
  <div class="login-header">
   <span class="login-logo">🦅</span>
   <div class="login-title">CROW-LINK</div>
   <div class="login-subtitle">// SECURITY PLATFORM — RESTRICTED ACCESS</div>
  </div>
  <div class="divider"></div>
  {% if error %}<div class="alert-error"><i class="fas fa-triangle-exclamation"></i>{{ error }}</div>{% endif %}
  <form method="POST" action="/login">
   <div class="form-group">
    <label class="form-label">البريد الإلكتروني</label>
    <div class="input-wrapper">
     <input type="email" name="email" class="form-control" placeholder="operator@crow-link.sec" required>
     <span class="input-icon"><i class="fas fa-at"></i></span>
    </div>
   </div>
   <div class="form-group">
    <label class="form-label">كلمة المرور</label>
    <div class="input-wrapper">
     <input type="password" name="password" class="form-control" placeholder="••••••••••••••" required>
     <span class="input-icon"><i class="fas fa-key"></i></span>
    </div>
   </div>
   <button type="submit" class="btn-login">
    <i class="fas fa-shield-halved" style="margin-left:8px;"></i> دخول آمن
   </button>
  </form>
  <div class="login-footer">
   <div class="footer-text"><span>CROW-LINK</span> Security Platform &copy; 2025</div>
   <div class="footer-text" style="margin-top:4px;">Unauthorized access is strictly prohibited</div>
  </div>
 </div>
</div>
<script>
const c=document.getElementById('m'),ctx=c.getContext('2d');
c.width=window.innerWidth;c.height=window.innerHeight;
const ch='CROW-LINK|01アイウエオカキ|ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',fs=13;
let cols=Math.floor(c.width/fs),drops=Array(cols).fill(1);
function d(){ctx.fillStyle='rgba(10,10,15,.05)';ctx.fillRect(0,0,c.width,c.height);ctx.fillStyle='#FFD700';ctx.font=fs+'px "Fira Code",monospace';for(let i=0;i<drops.length;i++){ctx.fillText(ch[Math.floor(Math.random()*ch.length)],i*fs,drops[i]*fs);if(drops[i]*fs>c.height&&Math.random()>.975)drops[i]=0;drops[i]++;}}
setInterval(d,60);window.onresize=()=>{c.width=window.innerWidth;c.height=window.innerHeight;cols=Math.floor(c.width/fs);drops=Array(cols).fill(1);};
</script>
</body></html>"""

DASHBOARD_HTML = r"""{% extends "base.html" %}
{% block title %}CROW-LINK — Dashboard{% endblock %}
{% block extra_css %}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:28px}
.stat-card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:20px;text-align:center;position:relative;overflow:hidden;transition:all .3s}
.stat-card:hover{border-color:var(--gold);transform:translateY(-2px);box-shadow:0 8px 30px rgba(255,215,0,.08)}
.stat-card::before{content:'';position:absolute;top:0;right:0;width:100%;height:2px;background:linear-gradient(90deg,transparent,var(--gold),transparent);opacity:.3}
.stat-number{font-size:2.4rem;font-weight:900;color:var(--gold);font-family:'Fira Code',monospace;text-shadow:0 0 20px rgba(255,215,0,.3)}
.stat-label{font-size:.72rem;color:var(--text-muted);margin-top:6px;font-family:'Fira Code',monospace;letter-spacing:1px}
.tools-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:16px}
.tool-card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:20px;text-decoration:none;color:inherit;display:block;transition:all .25s;position:relative;overflow:hidden}
.tool-card::before{content:'';position:absolute;top:0;right:0;width:100%;height:1px;background:var(--gold);transform:scaleX(0);transition:transform .3s;transform-origin:right}
.tool-card:hover{border-color:var(--gold-dim);transform:translateY(-2px);box-shadow:0 8px 30px rgba(255,215,0,.06)}
.tool-card:hover::before{transform:scaleX(1)}
.tool-card-header{display:flex;align-items:center;gap:12px;margin-bottom:10px}
.tool-card-icon{width:38px;height:38px;background:var(--gold-glow);border:1px solid var(--border-bright);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:.9rem;color:var(--gold);flex-shrink:0}
.tool-card-name{font-size:.9rem;font-weight:600;color:var(--text-primary)}
.tool-card-unit{font-size:.6rem;font-family:'Fira Code',monospace;color:var(--gold);letter-spacing:1px;opacity:.7}
.tool-card-desc{font-size:.75rem;color:var(--text-muted);line-height:1.5}
.section-title{font-size:.8rem;font-family:'Fira Code',monospace;color:var(--gold);letter-spacing:2px;margin-bottom:14px;display:flex;align-items:center;gap:10px}
.section-title::after{content:'';flex:1;height:1px;background:var(--border)}
.terminal-widget{background:rgba(0,0,0,.5);border:1px solid var(--border);border-radius:10px;padding:16px 20px;font-family:'Fira Code',monospace;font-size:.78rem;color:var(--gold);margin-bottom:28px;line-height:1.8}
.terminal-cursor{display:inline-block;width:8px;height:14px;background:var(--gold);animation:blink 1s step-end infinite;vertical-align:text-bottom;margin-right:2px}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
{% endblock %}
{% block content %}
<div class="page-header">
 <div class="header-icon">🦅</div>
 <div><h2>CROW-LINK Dashboard</h2><p>لوحة التحكم الرئيسية — 45 أداة أمنية متاحة</p></div>
 <div class="unit-badge">SYSTEM ONLINE</div>
</div>
<div class="terminal-widget">
 <span style="color:#666">crow-link@security:~$ </span>
 <span id="ttext"></span><span class="terminal-cursor"></span>
</div>
<div class="stats-grid">
 <div class="stat-card"><div class="stat-number">45</div><div class="stat-label">TOTAL TOOLS</div></div>
 <div class="stat-card"><div class="stat-number">5</div><div class="stat-label">UNITS ACTIVE</div></div>
 <div class="stat-card"><div class="stat-number">9</div><div class="stat-label">RECON TOOLS</div></div>
 <div class="stat-card"><div class="stat-number">9</div><div class="stat-label">WEB ARSENAL</div></div>
 <div class="stat-card"><div class="stat-number">9</div><div class="stat-label">NET WARFARE</div></div>
</div>
{% set sections=[
 ('🔍','RECON UNIT',[('/tools/whois','fa-globe','WHOIS Lookup','استعلام معلومات تسجيل النطاق'),('/tools/dns','fa-server','DNS Records','استعلام سجلات DNS'),('/tools/rdns','fa-arrows-rotate','Reverse DNS','البحث العكسي في DNS'),('/tools/subdomain','fa-sitemap','Subdomain Finder','اكتشاف النطاقات الفرعية'),('/tools/port-tcp','fa-plug','TCP Port Scanner','فحص المنافذ TCP'),('/tools/port-udp','fa-broadcast-tower','UDP Port Scanner','فحص المنافذ UDP'),('/tools/http-headers','fa-code','HTTP Headers','تحليل ترويسات HTTP'),('/tools/ssl','fa-lock','SSL Inspector','فحص شهادة SSL/TLS'),('/tools/robots','fa-robot','robots.txt Scanner','فحص ملف robots.txt')]),
 ('🧪','LAB UNIT',[('/tools/hash-gen','fa-hashtag','Hash Generator','توليد تجزئات MD5/SHA'),('/tools/hash-crack','fa-hammer','Hash Cracker','كسر التجزئات بقائمة كلمات'),('/tools/exif','fa-image','EXIF Extractor','استخراج بيانات EXIF'),('/tools/base64','fa-code','Base64','تشفير وفك تشفير Base64'),('/tools/url-encode','fa-link','URL Encode/Decode','ترميز وفك ترميز URL'),('/tools/hex-dump','fa-terminal','Hex Dump','عرض البيانات بتنسيق Hex'),('/tools/strings','fa-align-left','String Extractor','استخراج السلاسل النصية'),('/tools/stego','fa-eye-slash','Stego Detector','كشف البيانات المخفية'),('/tools/qr','fa-qrcode','QR Generator','توليد رموز QR')]),
 ('🌐','WEB ARSENAL',[('/tools/sqli','fa-database','SQLi Scanner','فحص SQL Injection'),('/tools/xss','fa-code','XSS Tester','فحص Cross-Site Scripting'),('/tools/csrf','fa-shield-halved','CSRF Tester','فحص CSRF'),('/tools/dirbust','fa-folder-open','Dir Brute Force','اكتشاف المسارات المخفية'),('/tools/admin-finder','fa-user-shield','Admin Finder','البحث عن لوحات التحكم'),('/tools/cookies','fa-cookie','Cookie Analyzer','تحليل Cookies'),('/tools/open-redirect','fa-arrow-right-from-bracket','Open Redirect','كشف ثغرات التوجيه'),('/tools/lfi','fa-file-code','LFI Tester','فحص LFI'),('/tools/wordpress','fa-wordpress','WordPress Scanner','فحص ثغرات WordPress')]),
 ('🛡️','NETWORK WARFARE',[('/tools/packet-sniffer','fa-wave-square','Packet Sniffer','التقاط حزم الشبكة'),('/tools/proxy-checker','fa-filter','Proxy Checker','فحص قوائم البروكسي'),('/tools/wol','fa-power-off','Wake-on-LAN','إيقاظ الأجهزة'),('/tools/ping-sweep','fa-satellite-dish','Ping Sweeper','مسح الشبكة'),('/tools/traceroute','fa-route','Traceroute','تتبع مسار الحزم'),('/tools/arp','fa-table-list','ARP Table','عرض جدول ARP'),('/tools/speed-test','fa-gauge-high','Speed Test','قياس سرعة الإنترنت'),('/tools/firewall-test','fa-fire','Firewall Tester','فحص الجدار الناري'),('/tools/vpn-detect','fa-mask','VPN Detector','كشف VPN')]),
 ('🖥️','COMMAND ROOM',[('/tools/gps-tracker','fa-map-location-dot','GPS Tracker','خريطة تتبع GPS'),('/tools/remote-console','fa-terminal','Remote Console','وحدة تحكم عن بعد'),('/tools/report-gen','fa-file-pdf','Report Generator','توليد تقارير PDF'),('/tools/ip-geo','fa-earth-africa','IP Geolocation','تحديد موقع IP'),('/tools/email-breach','fa-envelope-open-text','Email Breach','فحص تسريبات البريد'),('/tools/mac-lookup','fa-network-wired','MAC Lookup','استعلام MAC'),('/tools/phishing','fa-fish','Phishing Detector','كشف التصيد'),('/tools/malware-hash','fa-biohazard','Malware Hash','فحص البرامج الضارة'),('/tools/threat-map','fa-map','Threat Map','خريطة التهديدات')])
] %}
{% for icon,unit,tools in sections %}
<div style="margin-bottom:28px">
 <div class="section-title">{{icon}} {{unit}}</div>
 <div class="tools-grid">
  {% for path,fa,name,desc in tools %}
  <a href="{{path}}" class="tool-card">
   <div class="tool-card-header">
    <div class="tool-card-icon"><i class="fas {{fa}}"></i></div>
    <div><div class="tool-card-name">{{name}}</div><div class="tool-card-unit">{{unit}}</div></div>
   </div>
   <div class="tool-card-desc">{{desc}}</div>
  </a>
  {% endfor %}
 </div>
</div>
{% endfor %}
{% endblock %}
{% block extra_js %}
<script>
const lines=['Initializing CROW-LINK Security Platform...','Loading 45 security modules... [OK]','Establishing secure connection... [ENCRYPTED]','Matrix defense system active...','Welcome, Operator. All systems nominal.'];
let li=0,ci=0;const el=document.getElementById('ttext');
function t(){if(li>=lines.length){li=0;el.textContent='';setTimeout(t,2000);return;}const l=lines[li];if(ci<l.length){el.textContent+=l[ci];ci++;setTimeout(t,40);}else{el.textContent+='\n';li++;ci=0;setTimeout(t,600);}}
t();
</script>
{% endblock %}"""

TOOL_HTML = r"""{% extends "base.html" %}
{% block title %}{{ tool_name }} — CROW-LINK{% endblock %}
{% block extra_css %}
.tool-form{max-width:700px}
.geo-map{width:100%;height:300px;border-radius:10px;border:1px solid var(--border);margin-top:16px}
{% endblock %}
{% block content %}
<div class="page-header">
 <div class="header-icon">{{ unit_icon }}</div>
 <div><h2>{{ tool_name }}</h2><p>{{ tool_desc }}</p></div>
 <span class="unit-badge">{{ unit }}</span>
</div>
<div class="card tool-form">
 <form method="POST" {% if has_file %}enctype="multipart/form-data"{% endif %}>
  {% for field in fields %}
  <div class="form-group">
   <label class="form-label">{{ field.label }}</label>
   {% if field.type == 'textarea' %}
   <textarea name="{{ field.name }}" class="form-control" placeholder="{{ field.get('placeholder','') }}" rows="5">{{ request.form.get(field.name,'') }}</textarea>
   {% elif field.type == 'file' %}
   <input type="file" name="{{ field.name }}" class="form-control" {% if field.get('accept') %}accept="{{ field.accept }}"{% endif %}>
   {% elif field.type == 'select' %}
   <select name="{{ field.name }}" class="form-control">
    {% for val,lbl in field.options %}
    <option value="{{ val }}" {% if request.form.get(field.name)==val %}selected{% endif %}>{{ lbl }}</option>
    {% endfor %}
   </select>
   {% else %}
   <input type="text" name="{{ field.name }}" class="form-control" placeholder="{{ field.get('placeholder','') }}" value="{{ request.form.get(field.name,'') }}" autocomplete="off">
   {% endif %}
  </div>
  {% endfor %}
  <button type="submit" class="btn btn-primary">
   <i class="fas {% if fields %}fa-play{% else %}fa-refresh{% endif %}"></i>
   {% if fields %}تنفيذ{% else %}تحديث{% endif %}
  </button>
 </form>
</div>
{% if result %}
<div class="result-box {% if result.success %}success{% else %}error{% endif %}">
 <div class="result-header">
  {% if result.success %}
  <span style="color:var(--success);font-size:1.1rem">✓</span>
  <span class="result-status ok">OUTPUT</span>
  {% else %}
  <span style="color:var(--danger);font-size:1.1rem">✗</span>
  <span class="result-status err">ERROR</span>
  {% endif %}
  <span style="margin-right:auto;font-size:.7rem;color:var(--text-muted);font-family:'Fira Code',monospace">{{ tool_name }}</span>
  <button class="copy-btn" onclick="copyResult()">⎘ نسخ</button>
 </div>
 {% if result.success %}
 <pre class="result-data">{{ result.data }}</pre>
 {% else %}
 <div class="alert alert-danger"><i class="fas fa-triangle-exclamation"></i>{{ result.error }}</div>
 {% endif %}
</div>
{% endif %}
{% if qr_image %}
<div class="qr-output">
 <p style="color:var(--text-muted);font-size:.8rem;margin-bottom:12px">رمز QR المُولَّد:</p>
 <img src="data:image/png;base64,{{ qr_image }}" alt="QR Code">
 <br>
 <a href="data:image/png;base64,{{ qr_image }}" download="crow-link-qr.png" class="btn btn-secondary" style="margin-top:12px;display:inline-flex">
  <i class="fas fa-download"></i> تحميل
 </a>
</div>
{% endif %}
{% if geo_data %}
<div id="geo-map" class="geo-map"></div>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
document.addEventListener('DOMContentLoaded',function(){
 const map=L.map('geo-map').setView([{{ geo_data.lat }},{{ geo_data.lon }}],8);
 L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{attribution:'CROW-LINK',maxZoom:18}).addTo(map);
 L.marker([{{ geo_data.lat }},{{ geo_data.lon }}]).addTo(map)
  .bindPopup('<b style="color:#FFD700">{{ geo_data.city }}, {{ geo_data.country }}</b><br><span style="font-family:\'Fira Code\',monospace;font-size:11px">{{ geo_data.lat }}, {{ geo_data.lon }}</span>').openPopup();
});
</script>
{% endif %}
{% endblock %}"""

GPS_HTML = r"""{% extends "base.html" %}
{% block title %}GPS Tracker — CROW-LINK{% endblock %}
{% block extra_css %}
.map-container{width:100%;height:500px;border-radius:14px;border:1px solid var(--border);overflow:hidden}
.map-controls{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px;align-items:flex-end}
.coord-display{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:14px 20px;font-family:'Fira Code',monospace;font-size:.8rem;margin-top:14px;display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.coord-item{display:flex;gap:8px;align-items:center}
.coord-label{color:var(--gold);min-width:90px}
.track-history{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:14px 20px;font-family:'Fira Code',monospace;font-size:.75rem;margin-top:14px;max-height:200px;overflow-y:auto;direction:ltr}
.track-entry{color:var(--gold);padding:3px 0;border-bottom:1px solid rgba(255,215,0,.05)}
{% endblock %}
{% block content %}
<div class="page-header">
 <div class="header-icon">🖥️</div>
 <div><h2>Live GPS Tracker Map</h2><p>خريطة تتبع GPS مباشرة بـ OpenStreetMap + Leaflet.js</p></div>
 <span class="unit-badge">COMMAND ROOM</span>
</div>
<div class="card">
 <div class="map-controls">
  <div>
   <label class="form-label" style="margin-bottom:6px">إدخال إحداثيات يدوي</label>
   <div style="display:flex;gap:10px;flex-wrap:wrap">
    <input type="number" id="lat-input" class="form-control" placeholder="خط العرض (Lat)" step="0.0001" style="width:180px">
    <input type="number" id="lon-input" class="form-control" placeholder="خط الطول (Lon)" step="0.0001" style="width:180px">
   </div>
  </div>
  <button class="btn btn-primary" onclick="goToCoords()"><i class="fas fa-crosshairs"></i> انتقال</button>
  <button class="btn btn-secondary" onclick="getUserLocation()"><i class="fas fa-location-arrow"></i> موقعي</button>
  <button class="btn btn-secondary" onclick="startTracking()" id="track-btn"><i class="fas fa-play"></i> تتبع</button>
  <button class="btn btn-danger" onclick="clearTrack()"><i class="fas fa-trash"></i> مسح</button>
 </div>
 <div class="map-container"><div id="map" style="width:100%;height:100%"></div></div>
 <div class="coord-display">
  <div class="coord-item"><span class="coord-label">Latitude:</span><span id="disp-lat">—</span></div>
  <div class="coord-item"><span class="coord-label">Longitude:</span><span id="disp-lon">—</span></div>
  <div class="coord-item"><span class="coord-label">Accuracy:</span><span id="disp-acc">—</span></div>
  <div class="coord-item"><span class="coord-label">Speed:</span><span id="disp-speed">—</span></div>
  <div class="coord-item"><span class="coord-label">Altitude:</span><span id="disp-alt">—</span></div>
  <div class="coord-item"><span class="coord-label">Time:</span><span id="disp-time">—</span></div>
 </div>
 <div class="track-history" id="track-history"><div style="color:var(--text-muted)">// في انتظار بيانات GPS...</div></div>
</div>
{% endblock %}
{% block extra_js %}
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
const map=L.map('map',{center:[24.7136,46.6753],zoom:5});
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{attribution:'CROW-LINK GPS',maxZoom:19}).addTo(map);
const goldIcon=L.divIcon({html:'<div style="width:16px;height:16px;border-radius:50%;background:#FFD700;border:3px solid #000;box-shadow:0 0 12px #FFD700"></div>',className:'',iconSize:[16,16],iconAnchor:[8,8]});
let cm=null,tp=[],tl=null,wid=null,isT=false;
function upd(lat,lon,acc,sp,alt){document.getElementById('disp-lat').textContent=lat.toFixed(6);document.getElementById('disp-lon').textContent=lon.toFixed(6);document.getElementById('disp-acc').textContent=acc?acc.toFixed(0)+' m':'N/A';document.getElementById('disp-speed').textContent=sp?(sp*3.6).toFixed(1)+' km/h':'N/A';document.getElementById('disp-alt').textContent=alt?alt.toFixed(0)+' m':'N/A';document.getElementById('disp-time').textContent=new Date().toLocaleTimeString();}
function addLog(lat,lon){const h=document.getElementById('track-history'),e=document.createElement('div');e.className='track-entry';e.textContent=`[${new Date().toLocaleTimeString()}] lat=${lat.toFixed(6)}, lon=${lon.toFixed(6)}`;h.insertBefore(e,h.firstChild);if(h.children.length>50)h.removeChild(h.lastChild);}
function place(lat,lon,acc,sp,alt){if(cm)map.removeLayer(cm);cm=L.marker([lat,lon],{icon:goldIcon}).addTo(map);cm.bindPopup(`<div style="font-family:'Fira Code',sans-serif;font-size:11px"><b style="color:#FFD700">📍 موقع الهدف</b><br>Lat: ${lat.toFixed(6)}<br>Lon: ${lon.toFixed(6)}${acc?'<br>Accuracy: '+acc.toFixed(0)+'m':''}</div>`).openPopup();tp.push([lat,lon]);if(tl)map.removeLayer(tl);if(tp.length>1)tl=L.polyline(tp,{color:'#FFD700',weight:2,opacity:.6,dashArray:'5,5'}).addTo(map);upd(lat,lon,acc,sp,alt);addLog(lat,lon);}
function getUserLocation(){if(!navigator.geolocation){alert('Geolocation not supported');return;}navigator.geolocation.getCurrentPosition(p=>{const{latitude:la,longitude:lo,accuracy:ac,speed:sp,altitude:al}=p.coords;map.setView([la,lo],13);place(la,lo,ac,sp,al);},e=>alert('Error: '+e.message),{enableHighAccuracy:true,timeout:10000});}
function goToCoords(){const la=parseFloat(document.getElementById('lat-input').value),lo=parseFloat(document.getElementById('lon-input').value);if(isNaN(la)||isNaN(lo)){alert('Invalid coordinates');return;}map.setView([la,lo],12);place(la,lo,null,null,null);}
function startTracking(){const btn=document.getElementById('track-btn');if(isT){navigator.geolocation.clearWatch(wid);isT=false;btn.innerHTML='<i class="fas fa-play"></i> تتبع';btn.className='btn btn-secondary';}else{isT=true;btn.innerHTML='<i class="fas fa-stop"></i> إيقاف';btn.className='btn btn-danger';wid=navigator.geolocation.watchPosition(p=>{const{latitude:la,longitude:lo,accuracy:ac,speed:sp,altitude:al}=p.coords;map.panTo([la,lo]);place(la,lo,ac,sp,al);},e=>console.error(e),{enableHighAccuracy:true,maximumAge:1000,timeout:5000});}}
function clearTrack(){tp=[];if(tl){map.removeLayer(tl);tl=null;}if(cm){map.removeLayer(cm);cm=null;}document.getElementById('track-history').innerHTML='<div style="color:var(--text-muted)">// تم مسح المسار</div>';['disp-lat','disp-lon','disp-acc','disp-speed','disp-alt','disp-time'].forEach(id=>document.getElementById(id).textContent='—');}
map.on('click',e=>place(e.latlng.lat,e.latlng.lng,null,null,null));
window.addEventListener('load',getUserLocation);
</script>
{% endblock %}"""

THREAT_HTML = r"""{% extends "base.html" %}
{% block title %}Live Threat Map — CROW-LINK{% endblock %}
{% block extra_css %}
.map-container{width:100%;height:520px;border-radius:14px;border:1px solid var(--border);overflow:hidden}
.threat-legend{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:14px;font-size:.75rem;font-family:'Fira Code',monospace}
.legend-item{display:flex;align-items:center;gap:6px}
.legend-dot{width:10px;height:10px;border-radius:50%}
.threat-feed{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:10px;margin-top:16px;max-height:260px;overflow-y:auto;padding:4px}
.threat-item{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:10px 14px;font-family:'Fira Code',monospace;font-size:.72rem;animation:fi .4s ease}
@keyframes fi{from{opacity:0;transform:translateY(4px)}to{opacity:1}}
.threat-item.critical{border-color:rgba(255,0,0,.4)}.threat-item.high{border-color:rgba(255,71,87,.4)}.threat-item.medium{border-color:rgba(255,165,2,.4)}.threat-item.low{border-color:rgba(46,213,115,.3)}
.threat-item .threat-type{font-weight:700;color:var(--gold);margin-bottom:4px}
.threat-item .threat-meta{color:var(--text-muted)}
.threat-counter{display:flex;gap:20px;margin-bottom:16px;flex-wrap:wrap}
.counter-item{background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:10px 16px;text-align:center;min-width:100px}
.counter-num{font-size:1.6rem;font-weight:900;font-family:'Fira Code',monospace}
.counter-label{font-size:.6rem;color:var(--text-muted);letter-spacing:1px}
{% endblock %}
{% block content %}
<div class="page-header">
 <div class="header-icon">🖥️</div>
 <div><h2>Live Threat Map</h2><p>خريطة التهديدات الأمنية العالمية في الوقت الفعلي</p></div>
 <span class="unit-badge">COMMAND ROOM</span>
</div>
<div class="card">
 <div class="threat-counter">
  <div class="counter-item"><div class="counter-num" id="cnt-total" style="color:var(--gold)">0</div><div class="counter-label">TOTAL</div></div>
  <div class="counter-item"><div class="counter-num" id="cnt-critical" style="color:#f00">0</div><div class="counter-label">CRITICAL</div></div>
  <div class="counter-item"><div class="counter-num" id="cnt-high" style="color:#ff4757">0</div><div class="counter-label">HIGH</div></div>
  <div class="counter-item"><div class="counter-num" id="cnt-medium" style="color:#ffa502">0</div><div class="counter-label">MEDIUM</div></div>
  <div class="counter-item"><div class="counter-num" id="cnt-low" style="color:#2ed573">0</div><div class="counter-label">LOW</div></div>
 </div>
 <div class="threat-legend">
  <div class="legend-item"><div class="legend-dot" style="background:#f00;box-shadow:0 0 6px #f00"></div> Critical</div>
  <div class="legend-item"><div class="legend-dot" style="background:#ff4757;box-shadow:0 0 6px #ff4757"></div> High</div>
  <div class="legend-item"><div class="legend-dot" style="background:#ffa502;box-shadow:0 0 6px #ffa502"></div> Medium</div>
  <div class="legend-item"><div class="legend-dot" style="background:#2ed573;box-shadow:0 0 6px #2ed573"></div> Low</div>
  <div style="margin-right:auto;color:var(--text-muted)"><span class="status-dot green" style="display:inline-block"></span> تحديث كل 10 ثوانٍ</div>
 </div>
 <div class="map-container"><div id="threat-map" style="width:100%;height:100%"></div></div>
 <div style="margin-top:14px;margin-bottom:8px;font-size:.75rem;color:var(--text-muted);font-family:'Fira Code',monospace">// LIVE THREAT FEED</div>
 <div class="threat-feed" id="threat-feed"></div>
</div>
{% endblock %}
{% block extra_js %}
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
const map=L.map('threat-map',{center:[20,10],zoom:2,minZoom:2});
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{attribution:'CROW-LINK',maxZoom:19}).addTo(map);
const sc={critical:{color:'#f00',radius:18,opacity:.8},high:{color:'#ff4757',radius:14,opacity:.7},medium:{color:'#ffa502',radius:10,opacity:.6},low:{color:'#2ed573',radius:7,opacity:.5}};
let markers=[],cnts={total:0,critical:0,high:0,medium:0,low:0};
function addMarker(t){const c=sc[t.severity]||sc.low,m=L.circleMarker([t.lat,t.lon],{color:c.color,fillColor:c.color,fillOpacity:c.opacity,radius:c.radius,weight:2}).addTo(map);m.bindPopup(`<div style="font-family:'Fira Code',sans-serif;font-size:11px;background:#111;color:#e0e0e0;padding:4px"><b style="color:#FFD700">⚠ ${t.type}</b><br>Location: ${t.city}<br>IP: ${t.source_ip}<br>Severity: <span style="color:${c.color}">${t.severity.toUpperCase()}</span><br>Time: ${t.timestamp}</div>`);return m;}
function addFeed(t){const feed=document.getElementById('threat-feed'),i=document.createElement('div');i.className=`threat-item ${t.severity}`;const c=sc[t.severity]||sc.low;i.innerHTML=`<div class="threat-type" style="color:${c.color}">${t.type}</div><div class="threat-meta">📍 ${t.city}</div><div class="threat-meta">🕐 ${t.timestamp}</div><div class="threat-meta">🔗 ${t.source_ip}</div>`;feed.insertBefore(i,feed.firstChild);if(feed.children.length>30)feed.removeChild(feed.lastChild);}
function updateCnts(){document.getElementById('cnt-total').textContent=cnts.total;['critical','high','medium','low'].forEach(k=>document.getElementById('cnt-'+k).textContent=cnts[k]);}
function load(){fetch('/api/threat-feed').then(r=>r.json()).then(ts=>{markers.forEach(m=>map.removeLayer(m));markers=[];ts.forEach(t=>{markers.push(addMarker(t));cnts.total++;if(cnts[t.severity]!==undefined)cnts[t.severity]++;addFeed(t);});updateCnts();}).catch(e=>console.error(e));}
load();setInterval(load,10000);
for(let lat=-60;lat<=60;lat+=30)L.polyline([[lat,-180],[lat,180]],{color:'rgba(255,215,0,.03)',weight:.3,dashArray:'4,4'}).addTo(map);
for(let lon=-150;lon<=150;lon+=30)L.polyline([[-90,lon],[90,lon]],{color:'rgba(255,215,0,.03)',weight:.3,dashArray:'4,4'}).addTo(map);
</script>
{% endblock %}"""

# ═══════════════════════════════════════════════════════════
#  APP INIT — DictLoader so {% extends %} works inline
# ═══════════════════════════════════════════════════════════

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'crow-link-secret-2025-xK9!mR#vT')
app.jinja_loader = DictLoader({
    'base.html':       BASE_HTML,
    'login.html':      LOGIN_HTML,
    'dashboard.html':  DASHBOARD_HTML,
    'tool.html':       TOOL_HTML,
    'gps_tracker.html': GPS_HTML,
    'threat_map.html': THREAT_HTML,
})

VALID_EMAIL    = "zrougtaib@gmail.com"
VALID_PASSWORD = "#FFHUDT6O3jqu9cSBPo7eO"
UPLOAD_FOLDER  = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def login_required(f):
    @wraps(f)
    def dec(*a, **kw):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*a, **kw)
    return dec

def render(template, **kw):
    from flask import render_template
    return render_template(template, **kw)

# ═══════════════════════════════════════════════════════════
#  AUTH
# ═══════════════════════════════════════════════════════════

@app.route('/')
def index():
    return redirect(url_for('dashboard') if session.get('logged_in') else url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form.get('email') == VALID_EMAIL and request.form.get('password') == VALID_PASSWORD:
            session['logged_in'] = True
            session['user_email'] = request.form['email']
            return redirect(url_for('dashboard'))
        error = 'بيانات الاعتماد غير صحيحة. حاول مجدداً.'
    return render('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render('dashboard.html')

# ═══════════════════════════════════════════════════════════
#  RECON UNIT
# ═══════════════════════════════════════════════════════════

@app.route('/tools/whois', methods=['GET', 'POST'])
@login_required
def tool_whois():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        if target:
            try:
                if WHOIS_AVAILABLE:
                    result = {'success': True, 'data': str(whois_lib.whois(target))}
                else:
                    r = requests.get(f'https://api.whoisfreaks.com/v1.0/whois?whois=live&domainName={target}&apiKey=free', timeout=10)
                    result = {'success': True, 'data': r.text[:3000]}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='whois', tool_name='WHOIS Lookup', tool_desc='استعلام معلومات تسجيل النطاق',
                  unit='RECON UNIT', unit_icon='🔍',
                  fields=[{'name': 'target', 'label': 'النطاق أو عنوان IP', 'placeholder': 'example.com'}],
                  result=result)

@app.route('/tools/dns', methods=['GET', 'POST'])
@login_required
def tool_dns():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        if target:
            try:
                records = []
                if DNS_AVAILABLE:
                    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']:
                        try:
                            for ans in dns.resolver.resolve(target, rtype):
                                records.append(f"{rtype}: {ans}")
                        except Exception:
                            pass
                else:
                    for i in socket.getaddrinfo(target, None):
                        records.append(f"A: {i[4][0]}")
                result = {'success': True, 'data': '\n'.join(records) or 'لا توجد سجلات'}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='dns', tool_name='DNS Record Lookup', tool_desc='استعلام سجلات DNS للنطاق',
                  unit='RECON UNIT', unit_icon='🔍',
                  fields=[{'name': 'target', 'label': 'النطاق', 'placeholder': 'example.com'}], result=result)

@app.route('/tools/rdns', methods=['GET', 'POST'])
@login_required
def tool_rdns():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        if target:
            try:
                h = socket.gethostbyaddr(target)
                result = {'success': True, 'data': f"الاسم: {h[0]}\nالأسماء البديلة: {', '.join(h[1])}\nالعناوين: {', '.join(h[2])}"}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='rdns', tool_name='Reverse DNS Lookup', tool_desc='البحث العكسي في DNS',
                  unit='RECON UNIT', unit_icon='🔍',
                  fields=[{'name': 'target', 'label': 'عنوان IP', 'placeholder': '8.8.8.8'}], result=result)

@app.route('/tools/subdomain', methods=['GET', 'POST'])
@login_required
def tool_subdomain():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        if target:
            subs = ['www','mail','ftp','admin','blog','dev','api','app','test','staging','portal','vpn',
                    'ns1','ns2','smtp','pop','imap','webmail','remote','cdn','assets','img','static',
                    'media','help','support','docs','shop','store','forum','community','status',
                    'monitoring','dashboard','panel','secure','login','auth','mx','git','gitlab',
                    'jenkins','ci','analytics','tracking','beta','old','new','v2']
            found = []; lock = threading.Lock()
            def chk(s):
                try:
                    socket.setdefaulttimeout(2)
                    ip = socket.gethostbyname(f"{s}.{target}")
                    with lock: found.append(f"✓ {s}.{target} → {ip}")
                except Exception: pass
            threads = [threading.Thread(target=chk, args=(s,)) for s in subs]
            [t.start() for t in threads]; [t.join(timeout=5) for t in threads]
            result = {'success': True, 'data': '\n'.join(found) or 'لم يتم العثور على نطاقات فرعية'}
    return render('tool.html', tool_id='subdomain', tool_name='Subdomain Finder', tool_desc='اكتشاف النطاقات الفرعية',
                  unit='RECON UNIT', unit_icon='🔍',
                  fields=[{'name': 'target', 'label': 'النطاق', 'placeholder': 'example.com'}], result=result)

@app.route('/tools/port-tcp', methods=['GET', 'POST'])
@login_required
def tool_port_tcp():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        pr = request.form.get('port_range', '1-1024').strip()
        if target:
            try:
                p = pr.split('-'); s, e = int(p[0]), min(int(p[1]) if len(p) > 1 else int(p[0]), int(p[0]) + 200)
                open_ports = []; lock = threading.Lock()
                def scan(port):
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.settimeout(1)
                        if sock.connect_ex((target, port)) == 0:
                            try: svc = socket.getservbyport(port, 'tcp')
                            except: svc = 'unknown'
                            with lock: open_ports.append(f"Port {port}/TCP — OPEN ({svc})")
                        sock.close()
                    except Exception: pass
                threads = [threading.Thread(target=scan, args=(port,)) for port in range(s, e + 1)]
                [t.start() for t in threads]; [t.join(timeout=10) for t in threads]
                open_ports.sort(key=lambda x: int(x.split()[1].split('/')[0]))
                result = {'success': True, 'data': '\n'.join(open_ports) or 'لا توجد منافذ مفتوحة'}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='port-tcp', tool_name='Port Scanner (TCP)', tool_desc='فحص المنافذ TCP المفتوحة',
                  unit='RECON UNIT', unit_icon='🔍',
                  fields=[{'name': 'target', 'label': 'الهدف', 'placeholder': '192.168.1.1'},
                          {'name': 'port_range', 'label': 'نطاق المنافذ', 'placeholder': '1-1024'}], result=result)

@app.route('/tools/port-udp', methods=['GET', 'POST'])
@login_required
def tool_port_udp():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        pr = request.form.get('port_range', '1-100').strip()
        if target:
            try:
                p = pr.split('-'); s, e = int(p[0]), min(int(p[1]) if len(p) > 1 else int(p[0]), int(p[0]) + 100)
                results = []
                for port in range(s, e + 1):
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.settimeout(1)
                        sock.sendto(b'\x00' * 10, (target, port))
                        try: sock.recvfrom(1024); results.append(f"Port {port}/UDP — OPEN")
                        except socket.timeout: results.append(f"Port {port}/UDP — FILTERED")
                        sock.close()
                    except Exception: pass
                result = {'success': True, 'data': '\n'.join(results) or 'لا توجد نتائج'}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='port-udp', tool_name='Port Scanner (UDP)', tool_desc='فحص المنافذ UDP',
                  unit='RECON UNIT', unit_icon='🔍',
                  fields=[{'name': 'target', 'label': 'الهدف', 'placeholder': '192.168.1.1'},
                          {'name': 'port_range', 'label': 'نطاق المنافذ', 'placeholder': '1-100'}], result=result)

@app.route('/tools/http-headers', methods=['GET', 'POST'])
@login_required
def tool_http_headers():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        if target:
            try:
                if not target.startswith('http'): target = 'https://' + target
                resp = requests.get(target, timeout=10, allow_redirects=True,
                                    headers={'User-Agent': 'Mozilla/5.0 (CROW-LINK)'})
                sec = {'Strict-Transport-Security': '⚠️', 'X-Frame-Options': '⚠️',
                       'X-Content-Type-Options': '⚠️', 'Content-Security-Policy': '⚠️',
                       'X-XSS-Protection': '⚠️', 'Referrer-Policy': '⚠️'}
                for h in sec:
                    if h in resp.headers: sec[h] = f"✓ {resp.headers[h]}"
                out = "=== HTTP Headers ===\n" + '\n'.join(f"{k}: {v}" for k, v in resp.headers.items())
                out += "\n\n=== Security Headers ===\n" + '\n'.join(f"{k}: {v}" for k, v in sec.items())
                out += f"\n\nStatus: {resp.status_code} | Server: {resp.headers.get('Server','N/A')}"
                result = {'success': True, 'data': out}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='http-headers', tool_name='HTTP Header Analyzer', tool_desc='تحليل ترويسات HTTP وفحص الأمان',
                  unit='RECON UNIT', unit_icon='🔍',
                  fields=[{'name': 'target', 'label': 'URL', 'placeholder': 'https://example.com'}], result=result)

@app.route('/tools/ssl', methods=['GET', 'POST'])
@login_required
def tool_ssl():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        port = int(request.form.get('port', 443) or 443)
        if target:
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((target, port), timeout=10) as sock:
                    with ctx.wrap_socket(sock, server_hostname=target) as s:
                        cert = s.getpeercert(); ver = s.version(); ciph = s.cipher()
                subj = dict(x[0] for x in cert.get('subject', []))
                iss  = dict(x[0] for x in cert.get('issuer', []))
                sans = cert.get('subjectAltName', [])
                out  = f"SSL Version: {ver}\nCipher: {ciph[0]} ({ciph[1]} bit)\n\n"
                out += f"=== Certificate ===\nSubject: {subj.get('commonName','N/A')}\n"
                out += f"Issuer: {iss.get('organizationName','N/A')}\n"
                out += f"Valid From: {cert.get('notBefore','N/A')}\nValid Until: {cert.get('notAfter','N/A')}\n"
                if sans: out += f"SANs: {', '.join(s[1] for s in sans[:10])}"
                result = {'success': True, 'data': out}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='ssl', tool_name='SSL Certificate Inspector', tool_desc='فحص شهادة SSL/TLS',
                  unit='RECON UNIT', unit_icon='🔍',
                  fields=[{'name': 'target', 'label': 'النطاق', 'placeholder': 'example.com'},
                          {'name': 'port', 'label': 'المنفذ', 'placeholder': '443'}], result=result)

@app.route('/tools/robots', methods=['GET', 'POST'])
@login_required
def tool_robots():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        if target:
            try:
                if not target.startswith('http'): target = 'https://' + target
                resp = requests.get(f"{target.rstrip('/')}/robots.txt", timeout=10)
                if resp.status_code == 200:
                    lines = resp.text.split('\n')
                    dis = [l for l in lines if 'Disallow' in l]
                    sit = [l for l in lines if 'Sitemap' in l]
                    out = f"=== robots.txt ===\n{resp.text[:2000]}\n\n=== Analysis ===\n"
                    out += f"Disallowed: {len(dis)}\n" + '\n'.join(dis[:20])
                    out += f"\n\nSitemaps: {len(sit)}\n" + '\n'.join(sit)
                    result = {'success': True, 'data': out}
                else:
                    result = {'success': False, 'error': f'Status: {resp.status_code}'}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='robots', tool_name='robots.txt Scanner', tool_desc='فحص وتحليل ملف robots.txt',
                  unit='RECON UNIT', unit_icon='🔍',
                  fields=[{'name': 'target', 'label': 'URL الموقع', 'placeholder': 'https://example.com'}], result=result)

# ═══════════════════════════════════════════════════════════
#  LAB UNIT
# ═══════════════════════════════════════════════════════════

@app.route('/tools/hash-gen', methods=['GET', 'POST'])
@login_required
def tool_hash_gen():
    result = None
    if request.method == 'POST':
        text = request.form.get('text', '')
        if text:
            result = {'success': True, 'data': (
                f"MD5:    {hashlib.md5(text.encode()).hexdigest()}\n"
                f"SHA1:   {hashlib.sha1(text.encode()).hexdigest()}\n"
                f"SHA256: {hashlib.sha256(text.encode()).hexdigest()}\n"
                f"SHA512: {hashlib.sha512(text.encode()).hexdigest()}")}
    return render('tool.html', tool_id='hash-gen', tool_name='Hash Generator', tool_desc='توليد تجزئات MD5/SHA',
                  unit='LAB UNIT', unit_icon='🧪',
                  fields=[{'name': 'text', 'label': 'النص', 'placeholder': '...', 'type': 'textarea'}], result=result)

@app.route('/tools/hash-crack', methods=['GET', 'POST'])
@login_required
def tool_hash_crack():
    result = None
    if request.method == 'POST':
        target_hash = request.form.get('hash', '').strip().lower()
        words = [w.strip() for w in request.form.get('wordlist', '').split('\n')]
        if target_hash and words:
            found = None
            ht = {32: 'MD5', 40: 'SHA1', 64: 'SHA256'}.get(len(target_hash), 'Unknown')
            for w in words[:5000]:
                for algo in [hashlib.md5, hashlib.sha1, hashlib.sha256]:
                    if algo(w.encode()).hexdigest() == target_hash:
                        found = w; break
                if found: break
            result = ({'success': True, 'data': f"✓ تم كسر التجزئة!\nنوع: {ht}\nالقيمة: {found}"}
                      if found else {'success': True, 'data': f"✗ لم يتم العثور على تطابق من {len(words)} كلمة\nنوع: {ht}"})
    return render('tool.html', tool_id='hash-crack', tool_name='Hash Cracker', tool_desc='كسر التجزئات بقائمة كلمات',
                  unit='LAB UNIT', unit_icon='🧪',
                  fields=[{'name': 'hash', 'label': 'التجزئة المستهدفة', 'placeholder': 'e.g. 5f4dcc3b5aa765d61d8327deb882cf99'},
                          {'name': 'wordlist', 'label': 'قائمة الكلمات', 'placeholder': 'password\n123456\nadmin', 'type': 'textarea'}], result=result)

@app.route('/tools/exif', methods=['GET', 'POST'])
@login_required
def tool_exif():
    result = None
    if request.method == 'POST':
        f = request.files.get('file')
        if f and PIL_AVAILABLE:
            try:
                img = Image.open(f)
                exif = img._getexif()
                if exif:
                    result = {'success': True, 'data': "=== EXIF Metadata ===\n" +
                              '\n'.join(f"{TAGS.get(tid, tid)}: {val}" for tid, val in exif.items())}
                else:
                    result = {'success': True, 'data': f"Format: {img.format}\nSize: {img.size}\nMode: {img.mode}\n\nلا توجد بيانات EXIF"}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
        elif not PIL_AVAILABLE:
            result = {'success': False, 'error': 'مكتبة Pillow غير متاحة'}
    return render('tool.html', tool_id='exif', tool_name='Exif Metadata Extractor', tool_desc='استخراج بيانات EXIF من الصور',
                  unit='LAB UNIT', unit_icon='🧪',
                  fields=[{'name': 'file', 'label': 'رفع صورة', 'type': 'file', 'accept': 'image/*'}],
                  result=result, has_file=True)

@app.route('/tools/base64', methods=['GET', 'POST'])
@login_required
def tool_base64():
    result = None
    if request.method == 'POST':
        text = request.form.get('text', ''); action = request.form.get('action', 'encode')
        if text:
            try:
                if action == 'encode':
                    result = {'success': True, 'data': f"=== Base64 Encoded ===\n{base64.b64encode(text.encode()).decode()}"}
                else:
                    result = {'success': True, 'data': f"=== Base64 Decoded ===\n{base64.b64decode(text.encode()).decode('utf-8', errors='replace')}"}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='base64', tool_name='Base64 Encoder/Decoder', tool_desc='تشفير وفك تشفير Base64',
                  unit='LAB UNIT', unit_icon='🧪',
                  fields=[{'name': 'text', 'label': 'النص', 'placeholder': '...', 'type': 'textarea'},
                          {'name': 'action', 'label': 'العملية', 'type': 'select',
                           'options': [('encode', 'تشفير (Encode)'), ('decode', 'فك التشفير (Decode)')]}], result=result)

@app.route('/tools/url-encode', methods=['GET', 'POST'])
@login_required
def tool_url_encode():
    result = None
    if request.method == 'POST':
        text = request.form.get('text', ''); action = request.form.get('action', 'encode')
        if text:
            try:
                if action == 'encode':
                    result = {'success': True, 'data': f"=== URL Encoded ===\n{urllib.parse.quote(text, safe='')}"}
                else:
                    result = {'success': True, 'data': f"=== URL Decoded ===\n{urllib.parse.unquote(text)}"}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='url-encode', tool_name='URL Encoder/Decoder', tool_desc='ترميز وفك ترميز URL',
                  unit='LAB UNIT', unit_icon='🧪',
                  fields=[{'name': 'text', 'label': 'النص', 'placeholder': 'https://example.com/?q=hello world', 'type': 'textarea'},
                          {'name': 'action', 'label': 'العملية', 'type': 'select',
                           'options': [('encode', 'ترميز (Encode)'), ('decode', 'فك الترميز (Decode)')]}], result=result)

@app.route('/tools/hex-dump', methods=['GET', 'POST'])
@login_required
def tool_hex_dump():
    result = None
    if request.method == 'POST':
        f = request.files.get('file'); data = None
        if f: data = f.read(4096)
        elif request.form.get('text'): data = request.form['text'].encode('utf-8', errors='replace')
        if data is not None:
            lines = [f"{i:08x}  {' '.join(f'{b:02x}' for b in data[i:i+16]).ljust(48)}  |{''.join(chr(b) if 32<=b<127 else '.' for b in data[i:i+16])}|"
                     for i in range(0, len(data), 16)]
            result = {'success': True, 'data': '\n'.join(lines)}
    return render('tool.html', tool_id='hex-dump', tool_name='Hex Dump Viewer', tool_desc='عرض البيانات بتنسيق Hex',
                  unit='LAB UNIT', unit_icon='🧪',
                  fields=[{'name': 'text', 'label': 'النص', 'placeholder': 'Hello, World!', 'type': 'textarea'},
                          {'name': 'file', 'label': 'ملف (اختياري)', 'type': 'file'}], result=result, has_file=True)

@app.route('/tools/strings', methods=['GET', 'POST'])
@login_required
def tool_strings():
    result = None
    if request.method == 'POST':
        f = request.files.get('file'); ml = int(request.form.get('min_len', 4) or 4)
        if f:
            data = f.read()
            found = re.findall(rb'[ -~]{' + str(ml).encode() + rb',}', data)
            result = {'success': True, 'data': f"Found {len(found)} strings (min {ml}):\n\n" +
                      '\n'.join(s.decode('ascii', errors='replace') for s in found[:500])}
        elif request.form.get('text'):
            found = re.findall(r'[ -~]{' + str(ml) + r',}', request.form['text'])
            result = {'success': True, 'data': '\n'.join(found[:200])}
    return render('tool.html', tool_id='strings', tool_name='String Extractor', tool_desc='استخراج السلاسل النصية من الملفات',
                  unit='LAB UNIT', unit_icon='🧪',
                  fields=[{'name': 'file', 'label': 'رفع ملف', 'type': 'file'},
                          {'name': 'text', 'label': 'أو أدخل نصاً', 'placeholder': '...', 'type': 'textarea'},
                          {'name': 'min_len', 'label': 'الحد الأدنى للطول', 'placeholder': '4'}], result=result, has_file=True)

@app.route('/tools/stego', methods=['GET', 'POST'])
@login_required
def tool_stego():
    result = None
    if request.method == 'POST':
        f = request.files.get('file')
        if f and PIL_AVAILABLE:
            try:
                img = Image.open(f)
                out = f"=== Steganography Analysis ===\nFormat: {img.format}\nSize: {img.size[0]}x{img.size[1]}\nMode: {img.mode}\n"
                if img.mode in ('RGB', 'RGBA'):
                    pixels = list(img.getdata())[:1000]
                    ratio = sum(1 for p in pixels if p[0] & 1) / len(pixels)
                    out += f"\n=== LSB Analysis ===\nLSB Ratio: {ratio:.2%}\n"
                    out += "⚠️ نسبة مشبوهة" if .4 < ratio < .6 else "✓ نسبة طبيعية"
                result = {'success': True, 'data': out}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='stego', tool_name='Steganography Detector', tool_desc='كشف البيانات المخفية في الصور',
                  unit='LAB UNIT', unit_icon='🧪',
                  fields=[{'name': 'file', 'label': 'رفع صورة', 'type': 'file', 'accept': 'image/*'}],
                  result=result, has_file=True)

@app.route('/tools/qr', methods=['GET', 'POST'])
@login_required
def tool_qr():
    result = None; qr_image = None
    if request.method == 'POST':
        text = request.form.get('text', '')
        if text and QRCODE_AVAILABLE:
            try:
                qr = qrcode_lib.QRCode(version=1, error_correction=qrcode_lib.constants.ERROR_CORRECT_L, box_size=10, border=4)
                qr.add_data(text); qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                buf = BytesIO(); img.save(buf, format='PNG'); buf.seek(0)
                qr_image = base64.b64encode(buf.getvalue()).decode()
                result = {'success': True, 'data': f'تم توليد رمز QR لـ: {text}'}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
        elif not QRCODE_AVAILABLE:
            result = {'success': False, 'error': 'مكتبة qrcode غير متاحة'}
    return render('tool.html', tool_id='qr', tool_name='QR Code Generator', tool_desc='توليد رموز QR',
                  unit='LAB UNIT', unit_icon='🧪',
                  fields=[{'name': 'text', 'label': 'النص أو الرابط', 'placeholder': 'https://example.com'},
                          {'name': 'action', 'label': 'العملية', 'type': 'select', 'options': [('generate', 'توليد QR')]}],
                  result=result, qr_image=qr_image)

# ═══════════════════════════════════════════════════════════
#  WEB ARSENAL
# ═══════════════════════════════════════════════════════════

SQLI = ["'", "''", "' OR '1'='1", "' OR 1=1--", "1' UNION SELECT NULL--", "' OR SLEEP(3)--"]
XSS  = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', "javascript:alert(1)", '<svg onload=alert(1)>']

@app.route('/tools/sqli', methods=['GET', 'POST'])
@login_required
def tool_sqli():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip(); param = request.form.get('param', 'id').strip()
        if target:
            try:
                if not target.startswith('http'): target = 'http://' + target
                findings = []; sess = requests.Session()
                for pl in SQLI[:5]:
                    try:
                        r = sess.get(target, params={param: pl}, timeout=5)
                        for ind in ['error in your SQL', 'mysql_fetch', 'ORA-', 'syntax error', 'SQL syntax']:
                            if ind.lower() in r.text.lower():
                                findings.append(f"⚠️ SQLi مشتبه به — Payload: {pl}\n   مؤشر: '{ind}'"); break
                    except Exception: pass
                result = {'success': True, 'data': f"SQLi Scanner — {target}\n\n" +
                          ('\n'.join(findings) if findings else '✓ لم يتم اكتشاف ثغرات SQLi')}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='sqli', tool_name='SQLi Scanner', tool_desc='فحص ثغرات SQL Injection',
                  unit='WEB ARSENAL', unit_icon='🌐',
                  fields=[{'name': 'target', 'label': 'URL الهدف', 'placeholder': 'http://example.com/page'},
                          {'name': 'param', 'label': 'المعامل', 'placeholder': 'id'}], result=result)

@app.route('/tools/xss', methods=['GET', 'POST'])
@login_required
def tool_xss():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip(); param = request.form.get('param', 'q').strip()
        if target:
            try:
                if not target.startswith('http'): target = 'http://' + target
                findings = []; sess = requests.Session()
                for pl in XSS[:5]:
                    try:
                        r = sess.get(target, params={param: pl}, timeout=5)
                        if pl in r.text or urllib.parse.quote(pl) in r.text:
                            findings.append(f"⚠️ XSS مشتبه به — Payload: {pl}")
                    except Exception: pass
                result = {'success': True, 'data': f"XSS Scanner — {target}\n\n" +
                          ('\n'.join(findings) if findings else '✓ لم يتم اكتشاف ثغرات XSS')}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='xss', tool_name='XSS Tester', tool_desc='فحص ثغرات Cross-Site Scripting',
                  unit='WEB ARSENAL', unit_icon='🌐',
                  fields=[{'name': 'target', 'label': 'URL الهدف', 'placeholder': 'http://example.com/search'},
                          {'name': 'param', 'label': 'المعامل', 'placeholder': 'q'}], result=result)

@app.route('/tools/csrf', methods=['GET', 'POST'])
@login_required
def tool_csrf():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        if target:
            try:
                if not target.startswith('http'): target = 'http://' + target
                resp = requests.get(target, timeout=10)
                tokens = re.findall(r'(?:csrf|_token|authenticity_token)["\s]*(?::|=)\s*["\']?([a-zA-Z0-9_\-+/=]{20,})', resp.text, re.I)
                out  = f"CSRF Analysis — {target}\n\n"
                out += f"CSRF Token: {'✓ موجود' if tokens else '⚠️ مفقود'}\n"
                out += f"SameSite Cookie: {'✓' if 'SameSite' in resp.headers.get('Set-Cookie','') else '⚠️ مفقود'}\n"
                out += f"CORS: {resp.headers.get('Access-Control-Allow-Origin','⚠️ غير محدد')}\n"
                result = {'success': True, 'data': out}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='csrf', tool_name='CSRF Tester', tool_desc='فحص الحماية من CSRF',
                  unit='WEB ARSENAL', unit_icon='🌐',
                  fields=[{'name': 'target', 'label': 'URL الهدف', 'placeholder': 'http://example.com/form'}], result=result)

COMMON_DIRS = ['admin','login','wp-admin','phpmyadmin','dashboard','backup','config','uploads',
               'images','api','v1','v2','test','dev','staging','db','logs','tmp','files','assets',
               'static','js','css','img','media','download','user','account','auth','secure',
               'secret','private','manager','management','hidden']

@app.route('/tools/dirbust', methods=['GET', 'POST'])
@login_required
def tool_dirbust():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        if target:
            try:
                if not target.startswith('http'): target = 'http://' + target
                found = []; lock = threading.Lock()
                def chk(d):
                    try:
                        r = requests.get(f"{target.rstrip('/')}/{d}", timeout=5, allow_redirects=False)
                        if r.status_code in [200, 301, 302, 403]:
                            with lock: found.append(f"[{r.status_code}] /{d}")
                    except Exception: pass
                threads = [threading.Thread(target=chk, args=(d,)) for d in COMMON_DIRS]
                [t.start() for t in threads]; [t.join(timeout=15) for t in threads]
                result = {'success': True, 'data': f"Dir Brute Force — {target}\nTested: {len(COMMON_DIRS)}\n\n" +
                          ('\n'.join(sorted(found)) if found else '✓ لم يتم العثور على مسارات')}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='dirbust', tool_name='Directory Brute Forcer', tool_desc='اكتشاف المسارات المخفية',
                  unit='WEB ARSENAL', unit_icon='🌐',
                  fields=[{'name': 'target', 'label': 'URL الهدف', 'placeholder': 'http://example.com'}], result=result)

ADMIN_PATHS = ['admin','admin/login','administrator','admin.php','wp-admin','wp-login.php',
               'cpanel','webadmin','manage','management','manager','control','controlpanel',
               'adminpanel','backend','cms','portal','admin/login.php','login.php','dashboard']

@app.route('/tools/admin-finder', methods=['GET', 'POST'])
@login_required
def tool_admin_finder():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        if target:
            try:
                if not target.startswith('http'): target = 'http://' + target
                found = []; lock = threading.Lock()
                def chk(p):
                    try:
                        r = requests.get(f"{target.rstrip('/')}/{p}", timeout=5)
                        if r.status_code in [200, 301, 302, 403]:
                            t = re.search(r'<title>(.*?)</title>', r.text, re.I)
                            with lock: found.append(f"[{r.status_code}] /{p} — {(t.group(1)[:40] if t else 'N/A')}")
                    except Exception: pass
                threads = [threading.Thread(target=chk, args=(p,)) for p in ADMIN_PATHS]
                [t.start() for t in threads]; [t.join(timeout=20) for t in threads]
                result = {'success': True, 'data': f"Admin Finder — {target}\n\n" +
                          ('\n'.join(sorted(found)) if found else '✓ لم يتم العثور على لوحات تحكم')}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='admin-finder', tool_name='Admin Panel Finder', tool_desc='البحث عن لوحات التحكم المخفية',
                  unit='WEB ARSENAL', unit_icon='🌐',
                  fields=[{'name': 'target', 'label': 'URL الموقع', 'placeholder': 'http://example.com'}], result=result)

@app.route('/tools/cookies', methods=['GET', 'POST'])
@login_required
def tool_cookies():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        if target:
            try:
                if not target.startswith('http'): target = 'http://' + target
                resp = requests.get(target, timeout=10)
                raw  = resp.headers.get('Set-Cookie', '')
                out  = f"Cookie Analyzer — {target}\n\n"
                if resp.cookies:
                    for name, val in resp.cookies.items():
                        out += f"Cookie: {name}\n  Value: {val[:50]}{'...' if len(val)>50 else ''}\n"
                        out += f"  HttpOnly: {'✓' if 'httponly' in raw.lower() else '⚠️'}\n"
                        out += f"  Secure: {'✓' if 'secure' in raw.lower() else '⚠️'}\n"
                        out += f"  SameSite: {'✓' if 'samesite' in raw.lower() else '⚠️'}\n\n"
                else:
                    out += "لا توجد cookies\n"
                result = {'success': True, 'data': out}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='cookies', tool_name='Cookie Analyzer', tool_desc='تحليل Cookies وفحص الأمان',
                  unit='WEB ARSENAL', unit_icon='🌐',
                  fields=[{'name': 'target', 'label': 'URL الموقع', 'placeholder': 'http://example.com'}], result=result)

@app.route('/tools/open-redirect', methods=['GET', 'POST'])
@login_required
def tool_open_redirect():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip(); param = request.form.get('param', 'url').strip()
        if target:
            try:
                if not target.startswith('http'): target = 'http://' + target
                findings = []
                for pl in ['https://evil.com', '//evil.com', '/\\evil.com', 'javascript:alert(1)']:
                    try:
                        r = requests.get(target, params={param: pl}, timeout=5, allow_redirects=False)
                        loc = r.headers.get('Location', '')
                        if 'evil.com' in loc or 'javascript' in loc.lower():
                            findings.append(f"⚠️ Open Redirect — {param}={pl}\n   Location: {loc}")
                    except Exception: pass
                result = {'success': True, 'data': '\n'.join(findings) if findings else "✓ لم يتم اكتشاف ثغرات Open Redirect"}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='open-redirect', tool_name='Open Redirect Finder', tool_desc='اكتشاف ثغرات إعادة التوجيه',
                  unit='WEB ARSENAL', unit_icon='🌐',
                  fields=[{'name': 'target', 'label': 'URL الهدف', 'placeholder': 'http://example.com/redirect'},
                          {'name': 'param', 'label': 'المعامل', 'placeholder': 'url'}], result=result)

@app.route('/tools/lfi', methods=['GET', 'POST'])
@login_required
def tool_lfi():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip(); param = request.form.get('param', 'page').strip()
        if target:
            try:
                if not target.startswith('http'): target = 'http://' + target
                findings = []
                for pl in ['../etc/passwd', '../../etc/passwd', '../../../etc/passwd',
                           '%2e%2e%2fetc%2fpasswd', '/etc/passwd', '../windows/win.ini']:
                    try:
                        r = requests.get(target, params={param: pl}, timeout=5)
                        if any(i in r.text for i in ['root:x:', 'daemon:', '[boot loader]', 'extension=']):
                            findings.append(f"⚠️ LFI مكتشفة! — {param}={pl}")
                    except Exception: pass
                result = {'success': True, 'data': '\n'.join(findings) if findings else "✓ لم يتم اكتشاف ثغرات LFI"}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='lfi', tool_name='LFI Tester', tool_desc='فحص ثغرات Local File Inclusion',
                  unit='WEB ARSENAL', unit_icon='🌐',
                  fields=[{'name': 'target', 'label': 'URL الهدف', 'placeholder': 'http://example.com/page'},
                          {'name': 'param', 'label': 'المعامل', 'placeholder': 'page'}], result=result)

@app.route('/tools/wordpress', methods=['GET', 'POST'])
@login_required
def tool_wordpress():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        if target:
            try:
                if not target.startswith('http'): target = 'https://' + target
                resp = requests.get(target, timeout=10)
                is_wp = any(i in resp.text for i in ['/wp-content/', '/wp-includes/', 'WordPress'])
                out   = f"WordPress Scanner — {target}\n\nDetected: {'✓ نعم' if is_wp else '✗ لا'}\n"
                if is_wp:
                    v = re.search(r'content="WordPress (\d+\.\d+\.?\d*)"', resp.text)
                    if v: out += f"Version: {v.group(1)}\n"
                    out += "\n=== Security Checks ===\n"
                    for path, name in [('/wp-json/wp/v2/users','User Enum'),('/wp-login.php','Login'),('/xmlrpc.php','XML-RPC'),('/?author=1','Author Enum')]:
                        try:
                            r = requests.get(target.rstrip('/') + path, timeout=5)
                            out += f"{'⚠️' if r.status_code==200 else '✓'} {name}: {r.status_code}\n"
                        except: out += f"? {name}: timeout\n"
                result = {'success': True, 'data': out}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='wordpress', tool_name='WordPress Scanner', tool_desc='فحص ثغرات WordPress',
                  unit='WEB ARSENAL', unit_icon='🌐',
                  fields=[{'name': 'target', 'label': 'URL الموقع', 'placeholder': 'https://example.com'}], result=result)

# ═══════════════════════════════════════════════════════════
#  NETWORK WARFARE
# ═══════════════════════════════════════════════════════════

@app.route('/tools/packet-sniffer', methods=['GET', 'POST'])
@login_required
def tool_packet_sniffer():
    result = None
    if request.method == 'POST':
        iface = request.form.get('interface', 'any').strip()
        count = min(int(request.form.get('count', 10) or 10), 20)
        try:
            r = subprocess.run(['tcpdump', '-i', iface, '-c', str(count), '-n', '--immediate-mode'],
                               capture_output=True, text=True, timeout=15)
            result = {'success': True, 'data': r.stdout or r.stderr or "لم يتم التقاط حزم"}
        except FileNotFoundError:
            result = {'success': False, 'error': 'tcpdump غير متاح في هذا النظام'}
        except subprocess.TimeoutExpired:
            result = {'success': False, 'error': 'انتهت مهلة التقاط الحزم'}
        except Exception as e:
            result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='packet-sniffer', tool_name='Packet Sniffer', tool_desc='التقاط وتحليل حزم الشبكة',
                  unit='NETWORK WARFARE', unit_icon='🛡️',
                  fields=[{'name': 'interface', 'label': 'الواجهة', 'placeholder': 'any'},
                          {'name': 'count', 'label': 'عدد الحزم', 'placeholder': '10'}], result=result)

@app.route('/tools/proxy-checker', methods=['GET', 'POST'])
@login_required
def tool_proxy_checker():
    result = None
    if request.method == 'POST':
        proxies = [p.strip() for p in request.form.get('proxies', '').split('\n') if p.strip()]
        if proxies:
            results = []; lock = threading.Lock()
            def chk(p):
                px = p if p.startswith('http') else 'http://' + p
                try:
                    t0 = time.time()
                    r  = requests.get('https://api.ipify.org?format=json', proxies={'http':px,'https':px}, timeout=8)
                    with lock: results.append(f"✓ {p} — IP: {r.json().get('ip','?')} — {(time.time()-t0)*1000:.0f}ms")
                except Exception:
                    with lock: results.append(f"✗ {p} — DEAD")
            threads = [threading.Thread(target=chk, args=(p,)) for p in proxies[:20]]
            [t.start() for t in threads]; [t.join(timeout=15) for t in threads]
            result = {'success': True, 'data': f"Proxy Checker ({len(proxies)} proxies)\n\n" + '\n'.join(results)}
    return render('tool.html', tool_id='proxy-checker', tool_name='Proxy Checker', tool_desc='فحص وتحقق من قوائم البروكسي',
                  unit='NETWORK WARFARE', unit_icon='🛡️',
                  fields=[{'name': 'proxies', 'label': 'قائمة البروكسيات', 'placeholder': '192.168.1.1:8080\n10.0.0.1:3128', 'type': 'textarea'}], result=result)

@app.route('/tools/wol', methods=['GET', 'POST'])
@login_required
def tool_wol():
    result = None
    if request.method == 'POST':
        mac = request.form.get('mac', '').strip(); bcast = request.form.get('broadcast', '255.255.255.255').strip()
        if mac:
            try:
                mc = mac.replace(':','').replace('-','').replace('.','')
                if len(mc) != 12: raise ValueError('عنوان MAC غير صالح')
                pkt = bytes.fromhex('F' * 12 + mc * 16)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.sendto(pkt, (bcast, 9)); s.close()
                result = {'success': True, 'data': f"✓ تم إرسال Magic Packet إلى {mac} عبر {bcast}:9\nحجم: {len(pkt)} bytes"}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='wol', tool_name='Wake-on-LAN Tool', tool_desc='إيقاظ الأجهزة عبر الشبكة',
                  unit='NETWORK WARFARE', unit_icon='🛡️',
                  fields=[{'name': 'mac', 'label': 'عنوان MAC', 'placeholder': 'AA:BB:CC:DD:EE:FF'},
                          {'name': 'broadcast', 'label': 'Broadcast IP', 'placeholder': '255.255.255.255'}], result=result)

@app.route('/tools/ping-sweep', methods=['GET', 'POST'])
@login_required
def tool_ping_sweep():
    result = None
    if request.method == 'POST':
        network = request.form.get('network', '').strip()
        if network:
            try:
                base = '.'.join(network.split('.')[:3]); alive = []; lock = threading.Lock()
                def ping(ip):
                    try:
                        r = subprocess.run(['ping', '-c', '1', '-W', '1', ip], capture_output=True, timeout=3)
                        if r.returncode == 0:
                            with lock: alive.append(ip)
                    except Exception: pass
                ips = [f"{base}.{i}" for i in range(1, 51)]
                threads = [threading.Thread(target=ping, args=(ip,)) for ip in ips]
                [t.start() for t in threads]; [t.join(timeout=10) for t in threads]
                alive.sort(key=lambda x: int(x.split('.')[-1]))
                result = {'success': True, 'data': f"Ping Sweep: {base}.1-50\nOnline: {len(alive)}/50\n\n" +
                          ('\n'.join(f"✓ {ip}" for ip in alive) or '✗ لا توجد أجهزة تستجيب')}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='ping-sweep', tool_name='Ping Sweeper', tool_desc='مسح الشبكة لاكتشاف الأجهزة الحية',
                  unit='NETWORK WARFARE', unit_icon='🛡️',
                  fields=[{'name': 'network', 'label': 'الشبكة', 'placeholder': '192.168.1.0'}], result=result)

@app.route('/tools/traceroute', methods=['GET', 'POST'])
@login_required
def tool_traceroute():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        if target:
            try:
                r = subprocess.run(['traceroute', '-n', '-m', '20', target], capture_output=True, text=True, timeout=30)
                result = {'success': True, 'data': r.stdout or r.stderr}
            except subprocess.TimeoutExpired:
                result = {'success': False, 'error': 'انتهت المهلة الزمنية'}
            except FileNotFoundError:
                try:
                    r = subprocess.run(['tracepath', '-n', target], capture_output=True, text=True, timeout=30)
                    result = {'success': True, 'data': r.stdout or r.stderr}
                except Exception as e:
                    result = {'success': False, 'error': str(e)}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='traceroute', tool_name='Traceroute Visualizer', tool_desc='تتبع مسار الحزم عبر الشبكة',
                  unit='NETWORK WARFARE', unit_icon='🛡️',
                  fields=[{'name': 'target', 'label': 'الهدف', 'placeholder': '8.8.8.8 أو example.com'}], result=result)

@app.route('/tools/arp', methods=['GET', 'POST'])
@login_required
def tool_arp():
    try:
        r = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
        out = r.stdout or r.stderr
        if not out:
            r2 = subprocess.run(['ip', 'neigh'], capture_output=True, text=True, timeout=10)
            out = r2.stdout or r2.stderr
        result = {'success': True, 'data': f"=== ARP Table ===\n\n{out}"}
    except Exception as e:
        result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='arp', tool_name='ARP Table Viewer', tool_desc='عرض جدول ARP للشبكة المحلية',
                  unit='NETWORK WARFARE', unit_icon='🛡️', fields=[], result=result, auto_run=True)

@app.route('/tools/speed-test', methods=['GET', 'POST'])
@login_required
def tool_speed_test():
    result = None
    if request.method == 'POST':
        try:
            t0 = time.time()
            resp = requests.get('https://speed.cloudflare.com/__down?bytes=5000000', timeout=30, stream=True)
            total = sum(len(c) for c in resp.iter_content(65536))
            elapsed = time.time() - t0
            speed = (total * 8) / (elapsed * 1_000_000)
            result = {'success': True, 'data': f"=== Network Speed Test ===\nDownload: {speed:.2f} Mbps\nData: {total/1e6:.1f} MB in {elapsed:.1f}s\nLatency: ~{elapsed*100:.0f}ms (estimated)"}
        except Exception as e:
            result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='speed-test', tool_name='Network Speed Test', tool_desc='قياس سرعة الإنترنت',
                  unit='NETWORK WARFARE', unit_icon='🛡️', fields=[], result=result)

@app.route('/tools/firewall-test', methods=['GET', 'POST'])
@login_required
def tool_firewall_test():
    result = None
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        if target:
            try:
                SVC = {80:'HTTP',443:'HTTPS',22:'SSH',21:'FTP',25:'SMTP',3306:'MySQL',3389:'RDP',8080:'HTTP-Alt',8443:'HTTPS-Alt',9200:'Elasticsearch'}
                lines = []
                for port, svc in SVC.items():
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2)
                        status = '✓ مفتوح' if s.connect_ex((target, port)) == 0 else '✗ مغلق'
                        s.close(); lines.append(f"{status} — Port {port} ({svc})")
                    except Exception: lines.append(f"? Port {port} ({svc}) — Error")
                result = {'success': True, 'data': f"Firewall Tester — {target}\n\n" + '\n'.join(lines)}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='firewall-test', tool_name='Firewall Rule Tester', tool_desc='فحص قواعد الجدار الناري',
                  unit='NETWORK WARFARE', unit_icon='🛡️',
                  fields=[{'name': 'target', 'label': 'الهدف', 'placeholder': '192.168.1.1'}], result=result)

@app.route('/tools/vpn-detect', methods=['GET', 'POST'])
@login_required
def tool_vpn_detect():
    result = None
    if request.method == 'POST':
        ip = request.form.get('ip', '').strip()
        if not ip:
            try: ip = requests.get('https://api.ipify.org?format=json', timeout=5).json().get('ip', '')
            except: pass
        if ip:
            try:
                d = requests.get(f'http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,proxy,hosting,query', timeout=10).json()
                is_p = d.get('proxy', False); is_h = d.get('hosting', False)
                out  = f"VPN/Proxy Detector — {ip}\n\nCountry: {d.get('country','N/A')}\nISP: {d.get('isp','N/A')}\nOrg: {d.get('org','N/A')}\nAS: {d.get('as','N/A')}\n\n"
                out += f"Proxy/VPN: {'⚠️ نعم' if is_p else '✓ لا'}\nHosting/DC: {'⚠️ نعم' if is_h else '✓ لا'}\n"
                out += f"\nVerdict: {'⚠️ IP مشبوه' if (is_p or is_h) else '✓ IP عادي'}"
                result = {'success': True, 'data': out}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='vpn-detect', tool_name='VPN Detector', tool_desc='كشف استخدام VPN والبروكسي',
                  unit='NETWORK WARFARE', unit_icon='🛡️',
                  fields=[{'name': 'ip', 'label': 'عنوان IP (اتركه فارغاً للكشف التلقائي)', 'placeholder': '8.8.8.8'}], result=result)

# ═══════════════════════════════════════════════════════════
#  COMMAND ROOM
# ═══════════════════════════════════════════════════════════

@app.route('/tools/gps-tracker')
@login_required
def tool_gps_tracker():
    return render('gps_tracker.html')

@app.route('/tools/remote-console', methods=['GET', 'POST'])
@login_required
def tool_remote_console():
    result = None
    if request.method == 'POST':
        cmd = request.form.get('command', '').strip()
        ALLOWED = ['ls','pwd','whoami','id','date','uname','hostname','ifconfig','ip','netstat',
                   'ps','df','free','uptime','cat','echo','env','which','find','curl','ping',
                   'nslookup','dig','whois','traceroute','arp']
        if cmd:
            try:
                parts = cmd.split()
                if parts[0] not in ALLOWED:
                    result = {'success': False, 'error': f'الأمر "{parts[0]}" غير مسموح به'}
                else:
                    r = subprocess.run(parts, capture_output=True, text=True, timeout=15)
                    result = {'success': True, 'data': (r.stdout or r.stderr or '(لا يوجد مخرجات)')[:5000]}
            except subprocess.TimeoutExpired:
                result = {'success': False, 'error': 'انتهت مهلة تنفيذ الأمر'}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='remote-console', tool_name='Remote Command Console', tool_desc='تنفيذ الأوامر عن بعد',
                  unit='COMMAND ROOM', unit_icon='🖥️',
                  fields=[{'name': 'command', 'label': 'الأمر', 'placeholder': 'whoami', 'type': 'code'}], result=result)

@app.route('/tools/report-gen', methods=['GET', 'POST'])
@login_required
def tool_report_gen():
    result = None
    if request.method == 'POST':
        title = request.form.get('title', 'Security Report')
        target = request.form.get('target', '')
        findings = request.form.get('findings', '')
        recs = request.form.get('recommendations', '')
        if REPORTLAB_AVAILABLE:
            try:
                from reportlab.lib import colors
                from reportlab.platypus import HRFlowable
                buf = BytesIO()
                doc = SimpleDocTemplate(buf, pagesize=A4)
                styles = getSampleStyleSheet()
                story = [Paragraph(f"<b>{title}</b>", styles['Title']), Spacer(1, 0.3*inch),
                         HRFlowable(width="100%", color=colors.HexColor('#FFD700')), Spacer(1, 0.2*inch),
                         Paragraph(f"<b>Target:</b> {target}", styles['Normal']),
                         Paragraph(f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Normal']),
                         Paragraph(f"<b>By:</b> CROW-LINK Security Platform", styles['Normal']),
                         Spacer(1, 0.3*inch), Paragraph("<b>Findings:</b>", styles['Heading2'])]
                for l in findings.split('\n'):
                    if l.strip(): story.append(Paragraph(f"• {l}", styles['Normal']))
                story += [Spacer(1, 0.3*inch), Paragraph("<b>Recommendations:</b>", styles['Heading2'])]
                for l in recs.split('\n'):
                    if l.strip(): story.append(Paragraph(f"• {l}", styles['Normal']))
                doc.build(story); buf.seek(0)
                return send_file(buf, mimetype='application/pdf', as_attachment=True,
                                 download_name=f"crow-link-{datetime.now().strftime('%Y%m%d')}.pdf")
            except Exception as e:
                result = {'success': False, 'error': str(e)}
        else:
            result = {'success': True, 'data': f"=== {title} ===\nTarget: {target}\nDate: {datetime.now()}\n\n=== Findings ===\n{findings}\n\n=== Recommendations ===\n{recs}"}
    return render('tool.html', tool_id='report-gen', tool_name='Report Generator (PDF)', tool_desc='توليد تقارير أمنية احترافية',
                  unit='COMMAND ROOM', unit_icon='🖥️',
                  fields=[{'name': 'title', 'label': 'عنوان التقرير', 'placeholder': 'Security Assessment Report'},
                          {'name': 'target', 'label': 'الهدف', 'placeholder': 'example.com'},
                          {'name': 'findings', 'label': 'النتائج', 'placeholder': 'SQLi في /login.php\nXSS في حقل البحث', 'type': 'textarea'},
                          {'name': 'recommendations', 'label': 'التوصيات', 'placeholder': 'تحديث WAF\nتصحيح المدخلات', 'type': 'textarea'}], result=result)

@app.route('/tools/ip-geo', methods=['GET', 'POST'])
@login_required
def tool_ip_geo():
    result = None; geo_data = None
    if request.method == 'POST':
        ip = request.form.get('ip', '').strip()
        if not ip:
            try: ip = requests.get('https://api.ipify.org?format=json', timeout=5).json().get('ip', '')
            except: pass
        if ip:
            try:
                d = requests.get(f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query', timeout=10).json()
                if d.get('status') == 'success':
                    out  = f"IP Geolocation — {d.get('query')}\n\nCountry: {d.get('country')} ({d.get('countryCode')})\n"
                    out += f"Region: {d.get('regionName')}\nCity: {d.get('city')} {d.get('zip','')}\n"
                    out += f"Timezone: {d.get('timezone')}\nISP: {d.get('isp')}\nOrg: {d.get('org')}\n"
                    out += f"Coordinates: {d.get('lat')}, {d.get('lon')}"
                    geo_data = d; result = {'success': True, 'data': out}
                else:
                    result = {'success': False, 'error': d.get('message', 'فشل الاستعلام')}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='ip-geo', tool_name='IP Geolocation Lookup', tool_desc='تحديد موقع عنوان IP جغرافياً',
                  unit='COMMAND ROOM', unit_icon='🖥️',
                  fields=[{'name': 'ip', 'label': 'عنوان IP (اتركه فارغاً للكشف التلقائي)', 'placeholder': '8.8.8.8'}],
                  result=result, geo_data=geo_data)

@app.route('/tools/email-breach', methods=['GET', 'POST'])
@login_required
def tool_email_breach():
    result = None
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if email:
            try:
                out  = f"Email Breach Checker — {email}\n\n"
                resp = requests.get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}',
                                    headers={'User-Agent': 'CROW-LINK-Security', 'hibp-api-key': 'free'}, timeout=10)
                if resp.status_code == 200:
                    brs = resp.json()
                    out += f"⚠️ {len(brs)} اختراق مُكتشف!\n\n"
                    for b in brs[:10]:
                        out += f"• {b.get('Name')} ({b.get('BreachDate','N/A')})\n  {', '.join(b.get('DataClasses',[])[:5])}\n\n"
                elif resp.status_code == 404:
                    out += "✓ لا توجد بيانات عن اختراقات لهذا البريد\n"
                else:
                    out += f"Status: {resp.status_code} — يتطلب HIBP مفتاح API مدفوع للبحث الكامل\n"
                    domain = email.split('@')[1] if '@' in email else ''
                    if domain: out += f"Domain: {domain}"
                result = {'success': True, 'data': out}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='email-breach', tool_name='Email Breach Checker', tool_desc='فحص تسريبات البريد الإلكتروني',
                  unit='COMMAND ROOM', unit_icon='🖥️',
                  fields=[{'name': 'email', 'label': 'البريد الإلكتروني', 'placeholder': 'user@example.com'}], result=result)

@app.route('/tools/mac-lookup', methods=['GET', 'POST'])
@login_required
def tool_mac_lookup():
    result = None
    if request.method == 'POST':
        mac = request.form.get('mac', '').strip()
        if mac:
            try:
                resp = requests.get(f'https://api.macvendors.com/{mac}', headers={'User-Agent': 'CROW-LINK'}, timeout=10)
                vendor = resp.text if resp.status_code == 200 else 'غير معروف'
                mc  = mac.replace(':','').replace('-','').replace('.','')[:6].upper()
                out = f"MAC Lookup — {mac}\nOUI: {mc}\nVendor: {vendor}\n"
                out += f"Type: {'Multicast' if int(mc[:2],16)&1 else 'Unicast'}\n"
                out += f"Locally Administered: {'Yes' if int(mc[:2],16)&2 else 'No'}"
                result = {'success': True, 'data': out}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='mac-lookup', tool_name='MAC Address Lookup', tool_desc='تحديد الشركة المصنعة من عنوان MAC',
                  unit='COMMAND ROOM', unit_icon='🖥️',
                  fields=[{'name': 'mac', 'label': 'عنوان MAC', 'placeholder': 'AA:BB:CC:DD:EE:FF'}], result=result)

PHISH_KW = ['login','signin','verify','update','confirm','account','secure','banking','paypal',
            'amazon','google','microsoft','apple','facebook','instagram','support','alert']

@app.route('/tools/phishing', methods=['GET', 'POST'])
@login_required
def tool_phishing():
    result = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if url:
            try:
                score = 0; inds = []
                parsed = urllib.parse.urlparse(url if '://' in url else 'http://' + url)
                domain = parsed.netloc.lower()
                if re.match(r'\d+\.\d+\.\d+\.\d+', domain): score += 30; inds.append("⚠️ استخدام IP مباشر")
                if domain.count('.') > 3: score += 20; inds.append(f"⚠️ نطاق متعدد المستويات ({domain.count('.')})")
                for kw in PHISH_KW:
                    if kw in domain: score += 15; inds.append(f"⚠️ كلمة مفتاحية: '{kw}'"); break
                if len(domain) > 30: score += 10; inds.append(f"⚠️ نطاق طويل جداً")
                tld = domain.split('.')[-1] if '.' in domain else ''
                if tld in ['tk','ml','ga','cf','gq','xyz','top','click','link']: score += 25; inds.append(f"⚠️ امتداد مشبوه: .{tld}")
                verdict = '🔴 خطر عالي' if score >= 60 else ('🟡 مشبوه' if score >= 30 else '🟢 آمن نسبياً')
                out = f"Phishing Detector — {url}\n\nRisk Score: {min(score,100)}/100\nVerdict: {verdict}\n\n"
                out += "=== المؤشرات ===\n" + '\n'.join(inds) if inds else "✓ لا توجد مؤشرات تصيد"
                result = {'success': True, 'data': out}
            except Exception as e:
                result = {'success': False, 'error': str(e)}
    return render('tool.html', tool_id='phishing', tool_name='Phishing URL Detector', tool_desc='كشف روابط التصيد الاحتيالي',
                  unit='COMMAND ROOM', unit_icon='🖥️',
                  fields=[{'name': 'url', 'label': 'URL المشبوه', 'placeholder': 'https://suspicious-site.com/login'}], result=result)

@app.route('/tools/malware-hash', methods=['GET', 'POST'])
@login_required
def tool_malware_hash():
    result = None
    if request.method == 'POST':
        h = request.form.get('hash', '').strip()
        f = request.files.get('file')
        if f: h = hashlib.sha256(f.read()).hexdigest()
        if h:
            ht = {32:'MD5',40:'SHA1',64:'SHA256'}.get(len(h),'Unknown')
            out = f"Malware Hash Lookup\nHash: {h}\nType: {ht}\n\nVirusTotal: يتطلب مفتاح API للفحص الكامل\n\n"
            out += f"Manual check: https://www.virustotal.com/gui/file/{h}"
            result = {'success': True, 'data': out}
    return render('tool.html', tool_id='malware-hash', tool_name='Malware Hash Lookup', tool_desc='البحث عن التجزئات في قواعد البرامج الضارة',
                  unit='COMMAND ROOM', unit_icon='🖥️',
                  fields=[{'name': 'hash', 'label': 'التجزئة (MD5/SHA1/SHA256)', 'placeholder': 'e3b0c44298fc1c149afbf4c8996fb924...'},
                          {'name': 'file', 'label': 'أو ارفع ملفاً', 'type': 'file'}], result=result, has_file=True)

@app.route('/tools/threat-map')
@login_required
def tool_threat_map():
    return render('threat_map.html')

@app.route('/api/threat-feed')
@login_required
def api_threat_feed():
    import random
    threats = [
        {"lat": 40.71, "lon": -74.01, "city": "New York",     "type": "DDoS",               "severity": "high"},
        {"lat": 51.51, "lon": -0.13,  "city": "London",        "type": "SQLi",               "severity": "medium"},
        {"lat": 35.68, "lon": 139.65, "city": "Tokyo",         "type": "Malware",            "severity": "critical"},
        {"lat": 48.86, "lon": 2.35,   "city": "Paris",         "type": "Phishing",           "severity": "low"},
        {"lat": 55.76, "lon": 37.62,  "city": "Moscow",        "type": "Ransomware",         "severity": "critical"},
        {"lat": 39.90, "lon": 116.41, "city": "Beijing",       "type": "APT",                "severity": "critical"},
        {"lat": -33.87,"lon": 151.21, "city": "Sydney",        "type": "XSS",                "severity": "medium"},
        {"lat": 19.43, "lon": -99.13, "city": "Mexico City",   "type": "Botnet",             "severity": "high"},
        {"lat": 1.35,  "lon": 103.82, "city": "Singapore",     "type": "Port Scan",          "severity": "low"},
        {"lat": -23.55,"lon": -46.63, "city": "São Paulo",     "type": "Spam",               "severity": "medium"},
        {"lat": 28.61, "lon": 77.21,  "city": "New Delhi",     "type": "Credential Stuffing","severity": "high"},
        {"lat": 37.77, "lon": -122.42,"city": "San Francisco", "type": "Zero-Day",           "severity": "critical"},
        {"lat": 52.52, "lon": 13.41,  "city": "Berlin",        "type": "Man-in-Middle",      "severity": "medium"},
        {"lat": 25.20, "lon": 55.27,  "city": "Dubai",         "type": "Crypto Mining",      "severity": "medium"},
        {"lat": 37.57, "lon": 126.98, "city": "Seoul",         "type": "Defacement",         "severity": "low"},
    ]
    for t in threats:
        t['lat'] += random.uniform(-1.5, 1.5)
        t['lon'] += random.uniform(-1.5, 1.5)
        t['timestamp'] = datetime.now().strftime('%H:%M:%S')
        t['source_ip'] = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    return jsonify(threats)

# ═══════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"""
╔══════════════════════════════════════════╗
║      CROW-LINK Security Platform         ║
║      Running on http://0.0.0.0:{port}       ║
╚══════════════════════════════════════════╝
  Login:    zrougtaib@gmail.com
  Password: #FFHUDT6O3jqu9cSBPo7eO
""")
    app.run(host='0.0.0.0', port=port, debug=False)
