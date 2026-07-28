# LitesPanel — Full Deployment Guide

ফ্রেশ Ubuntu VPS-এ শূন্য থেকে LitesPanel চালানোর সম্পূর্ণ গাইড।
কমান্ডগুলো ইংরেজিতে (কপি-পেস্ট), ব্যাখ্যা বাংলায়।

**Repo:** https://github.com/hanif865/litespanel

---

## 0. যা লাগবে (Prerequisites)

- একটা **VPS** — Ubuntu **24.04 LTS** (বা 22.04), ন্যূনতম 1 CPU / 1 GB RAM (2GB+ ভালো)
- সার্ভারের **root পাসওয়ার্ড** ও **IP ঠিকানা** (হোস্ট থেকে পাবে)
- (ঐচ্ছিক, SSL-এর জন্য) একটা **ডোমেইন** যেটার DNS তুমি নিয়ন্ত্রণ করো

> এই গাইডে `YOUR_SERVER_IP` = তোমার VPS-এর IP, `panel.example.com` = তোমার প্যানেল ডোমেইন।

---

## ধাপ ১ — প্রথম লগইন ও সার্ভার সিকিউর করা

### ১.১ root দিয়ে লগইন
নিজের কম্পিউটারের টার্মিনাল (PowerShell/Terminal) থেকে:
```bash
ssh root@YOUR_SERVER_IP
```
(হোস্টের দেওয়া root পাসওয়ার্ড দাও)

### ১.২ সিস্টেম আপডেট
```bash
apt update && apt upgrade -y
```

### ১.৩ একটা non-root sudo ইউজার বানাও
```bash
adduser deploy
usermod -aG sudo deploy
```
(একটা পাসওয়ার্ড দাও, নাম-টাম Enter চেপে স্কিপ করতে পারো)

### ১.৪ SSH key সেটআপ (পাসওয়ার্ডের বদলে key দিয়ে লগইন)

**নিজের কম্পিউটারে** (আলাদা টার্মিনালে) একবার key বানাও (আগে বানানো থাকলে স্কিপ):
```bash
ssh-keygen -t ed25519 -C "litespanel"
```

**public key দেখো ও কপি করো:**
```bash
type $env:USERPROFILE\.ssh\id_ed25519.pub    # Windows PowerShell
# অথবা Linux/Mac: cat ~/.ssh/id_ed25519.pub
```

**সার্ভারে (root হিসেবে) key বসাও** — `PASTE_KEY` জায়গায় উপরের পুরো লাইনটা দাও:
```bash
mkdir -p /home/deploy/.ssh
echo "PASTE_KEY" >> /home/deploy/.ssh/authorized_keys
chown -R deploy:deploy /home/deploy/.ssh
chmod 700 /home/deploy/.ssh && chmod 600 /home/deploy/.ssh/authorized_keys
```

**নতুন টার্মিনালে টেস্ট করো** (পুরনোটা খোলা রেখে):
```bash
ssh deploy@YOUR_SERVER_IP
```
key দিয়ে ঢুকতে পারলে ✅

### ১.৫ পাসওয়ার্ড ও root লগইন বন্ধ করো
deploy সেশনে:
```bash
printf 'PasswordAuthentication no\nPermitRootLogin no\nKbdInteractiveAuthentication no\n' | sudo tee /etc/ssh/sshd_config.d/00-hardening.conf
sudo sshd -t && sudo systemctl restart ssh
```
যাচাই: `sudo sshd -T | grep -Ei 'passwordauthentication|permitrootlogin'` → দুটোই `no` হওয়া উচিত।

### ১.৬ ফায়ারওয়াল
minimal ইমেজে `ufw` না-ও থাকতে পারে; ইনস্টল করে পোর্ট খুলে enable করো
(nginx এখনো নেই, তাই `'Nginx Full'` প্রোফাইলের বদলে সরাসরি পোর্ট নম্বর):
```bash
sudo apt install -y ufw
sudo ufw allow 22/tcp && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp
sudo ufw --force enable
```

---

## ধাপ ২ — এক কমান্ডে পুরো প্যানেল ইনস্টল 🚀

deploy সেশনে (SSL ছাড়া, IP দিয়ে অ্যাকসেস):
```bash
curl -fsSL https://raw.githubusercontent.com/hanif865/litespanel/main/install.sh | sudo bash
```

**অথবা ডোমেইন সহ (অটো Let's Encrypt SSL)** — আগে ধাপ ৩-এর DNS সেট করে নাও:
```bash
curl -fsSL https://raw.githubusercontent.com/hanif865/litespanel/main/install.sh | sudo bash -s -- panel.example.com
```

এই এক কমান্ড যা ইনস্টল ও কনফিগার করে:
`nginx` · `MySQL` · `PHP 8.3-FPM` · `certbot` · `phpMyAdmin` · প্যানেল (systemd সার্ভিস) · nginx reverse proxy · ফায়ারওয়াল।

শেষে দেখাবে:
```
✓ LitesPanel is installed and running.
Panel URL:  https://panel.example.com   (বা http://YOUR_SERVER_IP)
Username:   admin
Password:   ********      ← এটা সেভ করে রাখো
```

---

## ধাপ ৩ — ডোমেইন কানেক্ট করা (DNS)

তোমার ডোমেইন যেখান থেকে কিনেছ (Namecheap, GoDaddy, Cloudflare ইত্যাদি) — সেখানকার **DNS management**-এ যাও।

### ৩.১ প্যানেলের জন্য
একটা **A রেকর্ড** যোগ করো:

| Type | Name/Host | Value | TTL |
|------|-----------|-------|-----|
| A | `panel` (বা `@`) | `YOUR_SERVER_IP` | Auto/3600 |

মানে `panel.example.com` → তোমার VPS-এর IP।

### ৩.২ যে সাইটগুলো হোস্ট করবে
প্রতিটা হোস্ট-করা ডোমেইনের জন্যও A রেকর্ড দাও:

| Type | Name/Host | Value |
|------|-----------|-------|
| A | `@` | `YOUR_SERVER_IP` |
| A | `www` | `YOUR_SERVER_IP` |

### ৩.৩ DNS প্রোপাগেশন চেক
```bash
dig +short panel.example.com
```
IP ঠিকঠাক দেখালে (৫-৩০ মিনিট লাগতে পারে) → তারপর ধাপ ২-এর ডোমেইন-সহ কমান্ড চালিয়ে SSL নাও, অথবা:
```bash
sudo certbot --nginx -d panel.example.com
```

> **নোট:** এখন DNS তোমার registrar/Cloudflare-এ ম্যানেজ হবে। প্যানেলের Zone Editor-টা ভবিষ্যতে নিজের নেমসার্ভার (BIND) দিয়ে DNS হোস্ট করার জন্য — সেটা এখনো সেটআপ করা নেই।

---

## ধাপ ৪ — ইমেইল / Webmail (ঐচ্ছিক)

মেইল সার্ভার + Roundcube webmail চাই হলে, প্যানেল ইনস্টলের পর:
```bash
curl -fsSL https://raw.githubusercontent.com/hanif865/litespanel/main/setup-mail.sh | sudo bash
```
এটা Postfix + Dovecot + Roundcube বসায়, webmail থাকে `/webmail`-এ।

**ইমেইল কাজ করতে DNS রেকর্ড** (registrar-এ):

| Type | Name | Value |
|------|------|-------|
| MX | `@` | `panel.example.com` (priority 10) |
| A | `mail` | `YOUR_SERVER_IP` |
| TXT (SPF) | `@` | `v=spf1 a mx ~all` |

> ⚠️ Gmail-এ ইনবক্সে যেতে DKIM + PTR (reverse DNS) + port 25 আনব্লকড লাগবে — এগুলো হোস্ট ও DNS-এর ব্যাপার।

---

## ধাপ ৫ — প্রথম লগইন

1. ব্রাউজারে যাও: `https://panel.example.com` (বা `http://YOUR_SERVER_IP`)
2. লগইন: `admin` / (ইনস্টলারের দেওয়া পাসওয়ার্ড)
3. **সাথে সাথে পাসওয়ার্ড বদলাও** — নিচে "পাসওয়ার্ড বদলানো" দেখো
4. **User Manager** থেকে হোস্টিং অ্যাকাউন্ট বানাও → প্রতিটা আলাদা Linux ইউজার + আইসোলেটেড

---

## 🔄 আপডেট করা (Updating)

নতুন ভার্সন এলে — **একই এক কমান্ড আবার চালাও**। এটা GitHub থেকে নতুন কোড নামায়, reinstall করে, **তোমার admin পাসওয়ার্ড ও সব ডাটা অক্ষত রাখে**:
```bash
cd ~ && curl -fsSL https://raw.githubusercontent.com/hanif865/litespanel/main/install.sh | sudo bash
```
স্কিমা পরিবর্তন থাকলে Alembic migration নিজে থেকে চলে (কিছু হারাবে না)।

---

## 🛠️ দরকারি কমান্ড (Operations)

```bash
# প্যানেল সার্ভিস
sudo systemctl status litespanel      # অবস্থা
sudo systemctl restart litespanel     # রিস্টার্ট
sudo journalctl -u litespanel -f      # লাইভ লগ

# nginx
sudo nginx -t                         # কনফিগ টেস্ট
sudo systemctl reload nginx

# লগ
sudo journalctl -u litespanel -n 100  # প্যানেল লগ
sudo tail -f /var/log/nginx/error.log
sudo tail -f /var/log/mail.log        # মেইল (setup-mail.sh দিলে)
```

### পাসওয়ার্ড / কনফিগ বদলানো
```bash
sudo nano /etc/litespanel.env         # PANEL_ADMIN_PASSWORD ইত্যাদি বদলাও
sudo systemctl restart litespanel     # তারপর রিস্টার্ট
```

---

## 📁 ফাইল ও ডিরেক্টরি রেফারেন্স

| জিনিস | পথ |
|-------|-----|
| প্যানেল কোড | `/opt/litespanel` |
| কনফিগ + সিক্রেট | `/etc/litespanel.env` |
| ডাটাবেস + স্টেট | `/var/lib/litespanel` |
| সার্ভিস | `/etc/systemd/system/litespanel.service` |
| হোস্টিং অ্যাকাউন্টের ফাইল | `/home/<account>/<domain>/public_html` |
| nginx সাইট কনফিগ | `/etc/nginx/sites-enabled/` |
| phpMyAdmin | `/usr/share/phpmyadmin` → `/phpmyadmin` |
| Roundcube webmail | `/usr/share/roundcube` → `/webmail` |

---

## ⚙️ কনফিগ অপশন (`/etc/litespanel.env`)

| Variable | কাজ |
|----------|-----|
| `PANEL_PROVIDER` | `linux` (প্রোডাকশন) বা `demo` |
| `PANEL_SECRET_KEY` | সেশন signing key (গোপন রাখো) |
| `PANEL_ADMIN_USER` / `PANEL_ADMIN_PASSWORD` | admin লগইন |
| `PANEL_HTTPS` | `true` — HTTPS-এ থাকলে Secure cookie (SSL সেটআপে অটো হয়) |
| `PANEL_PHPMYADMIN_URL` | `/phpmyadmin` |
| `PANEL_WEBMAIL_URL` | `/webmail` (setup-mail.sh দিলে) |
| `PANEL_SERVER_IP` | DNS ডিফল্ট রেকর্ডের IP |

---

## 🩹 সমস্যা হলে (Troubleshooting)

| সমস্যা | করণীয় |
|--------|--------|
| প্যানেল খুলছে না | `sudo systemctl status litespanel` ও `sudo journalctl -u litespanel -n 50` দেখো |
| 502 Bad Gateway | প্যানেল সার্ভিস বন্ধ — `sudo systemctl restart litespanel` |
| SSL হয়নি | DNS ঠিকমতো IP-তে পয়েন্ট করছে? `dig +short panel.example.com` → তারপর `sudo certbot --nginx -d panel.example.com` |
| PHP সাইট চলছে না | `sudo systemctl status php8.3-fpm`; সাইট বানানোর পর প্যানেল vhost লেখে |
| Webmail লগইন হচ্ছে না | `/var/log/dovecot.log` ও `/var/log/mail.log` দেখো |
| firewall আটকাচ্ছে | `sudo ufw status` — 80,443,22 allow আছে কিনা |

---

## 🔐 নিরাপত্তা চেকলিস্ট

- [x] SSH key-only লগইন, root/password বন্ধ
- [x] ফায়ারওয়াল (ufw) চালু
- [x] প্যানেলে CSRF, rate-limit, security headers
- [x] অ্যাকাউন্ট আইসোলেশন (আলাদা system user + PHP-FPM pool)
- [ ] **প্রথম লগইনেই admin পাসওয়ার্ড বদলাও**
- [ ] HTTPS চালু করো (ডোমেইন + certbot)
- [ ] নিয়মিত `apt upgrade` ও প্যানেল আপডেট
