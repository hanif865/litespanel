# 🔒 LitesPanel — পূর্ণ প্রজেক্ট অডিট রিপোর্ট

> স্ট্যাটিক অডিট — পুরো কোডবেস (`app/routers/*`, `app/providers/linux.py`,
> `security.py`, `middleware.py`, `crypto.py`, `config.py`, `models.py`,
> `main.py`, templates)। নিচের সব `linux` provider–সংশ্লিষ্ট বাগ
> **লাইভ সাইটে (provider=linux) প্রযোজ্য**; demo provider বেশিরভাগ থেকে নিরাপদ।
>
> তারিখ: 2026-07-31 · প্রতিটা আইটেমে `- [ ]` চেকবক্স — ফিক্স হলে `- [x]` কর।

---

## 🔴 CRITICAL — এখনই ঠিক করা দরকার

যেকোনো সাধারণ ইউজার root/cross-tenant দখল নিতে পারে।

### - [ ] ১. Cron → সরাসরি root RCE
- **ফাইল:** `app/routers/cron.py:57`, `cron.py:34` → `app/providers/linux.py:454`
- **সমস্যা:** `command` ফর্ম ফিল্ড শুধু "খালি নয়" চেক হয় (`cron.py:66`), স্যানিটাইজ নেই।
  `f"{j.schedule} {j.command}"` বানিয়ে `crontab -` দিয়ে **root এর crontab** এ লেখা হয়।
  যেকোনো ইউজার নিজের কমান্ড root হিসেবে চালাতে পারে = সম্পূর্ণ সার্ভার দখল।
  (schedule ফিল্ড `_FIELD_RE` দিয়ে যাচাই হয়, command হয় না।)
- **ফিক্স:** command allowlist/escape; crontab root নয়, per-user (`crontab -u <user>`) এ লেখো।

### - [ ] ২. Cron জব সব টেন্যান্টে গ্লোবাল
- **ফাইল:** `app/routers/cron.py:33`
- **সমস্যা:** `_sync` সব ইউজারের `CronJob` সিলেক্ট করে (`owner_id` ফিল্টার নেই),
  একটাই root crontab এ লেখে — একজনের জব আরেকজনেরটা ওভাররাইট করে।
- **ফিক্স:** `owner_id` দিয়ে ফিল্টার + প্রতি ইউজারের crontab আলাদা।

### - [ ] ৩. Backup restore → cross-tenant ফাইল ও DB দখল
- **ফাইল:** `app/routers/backups.py:103` → `app/providers/linux.py:648`, `linux.py:670`
- **সমস্যা:** যেকোনো ইউজার নিজের zip আপলোড করতে পারে; আর্কাইভের ভেতরের path অনুযায়ী
  `/var/www` তে ফাইল লেখা হয় কিন্তু **মালিকানা চেক নেই** → অন্য টেন্যান্টের docroot এ
  webshell লিখে RCE, আর `databases/<name>.sql` panel MySQL admin দিয়ে যেকোনো DB-তে চলে।
  `safe_extract_path` শুধু `/var/www` থেকে বের হওয়া ঠেকায়, ভেতরে অন্য টেন্যান্টে যাওয়া নয়।
  এছাড়া `linux.py:670` mysql returncode চেক করে না (নীরব ব্যর্থতা)।
- **ফিক্স:** restore path কে ইউজারের নিজের docroot/DB-তে scope কর; mysql returncode চেক কর।

### - [ ] ৪. SQL Console → MySQL admin হিসেবে যেকোনো DB
- **ফাইল:** `app/routers/dbconsole.py:218` → `app/providers/linux.py:463`
- **সমস্যা:** ownership শুধু ড্রপডাউনের `selected` DB-তে চেক হয়, raw `sql` টেক্সট
  `mysql` দিয়ে **panel admin (socket auth)** হিসেবে চলে →
  `USE other_db; SELECT/DROP ...` দিয়ে যেকোনো টেন্যান্টের DB পড়া/মোছা যায়।
  (demo নিরাপদ — আলাদা SQLite ফাইল।)
- **ফিক্স:** raw sql নির্বাচিত DB-তে scope কর; panel-admin socket নয়, per-DB user দিয়ে চালাও।

### - [ ] ৫. ডিফল্ট admin/admin ক্রেডেনশিয়াল
- **ফাইল:** `app/config.py:45-46`
- **সমস্যা:** `ADMIN_USERNAME`/`ADMIN_PASSWORD` env না দিলে `admin`/`admin` দিয়ে বুটস্ট্র্যাপ।
- **ফিক্স:** env বাধ্যতামূলক কর; না থাকলে স্টার্টআপে ব্যর্থ হও (silent fallback নয়)।

### - [ ] ৬. Domain/FQDN যাচাই ছাড়া nginx-injection + path-traversal
- **ফাইল:** `app/providers/linux.py:118-124` (`_vhost`) + 132/139/148/269/276/369/415/432
- **সমস্যা:** `domain`/`fqdn` কখনো ভ্যালিডেট হয় না → কারসাজি ডোমেইন দিয়ে nginx কনফিগে
  ডিরেক্টিভ ইনজেক্ট বা `/var/www/<domain>` path traversal করে root-owned ফাইল লেখা যায়।
- **ফিক্স:** সব entry-point এ কড়া domain regex (`^[a-z0-9.-]+$` + length) প্রয়োগ কর।

---
## 🟠 HIGH

### - [ ] ৭. Ephemeral SECRET_KEY
- **ফাইল:** `app/config.py:41` → `app/crypto.py:26`
- **সমস্যা:** env-এ না থাকলে প্রতি প্রসেসে র‍্যান্ডম SECRET_KEY। ফলে (ক) রিস্টার্ট/মাল্টি-worker এ
  সব সেশন কুকি ভেঙে যায়; (খ) `crypto.py:26` এই key থেকে ডেরাইভ করে, তাই restart এর পর
  at-rest এনক্রিপ্ট করা MySQL পাসওয়ার্ড আর ডিক্রিপ্ট হয় না (ডেটা লস)।
- **ফিক্স:** SECRET_KEY env বাধ্যতামূলক কর; না থাকলে স্টার্টআপে ব্যর্থ হও।

### - [ ] ৮. DNS zone injection
- **ফাইল:** `app/routers/dns.py` → `app/providers/linux.py:541-548`
- **সমস্যা:** non-A/AAAA রেকর্ডের `value` verbatim BIND zone-এ লেখা হয় → newline দিয়ে
  zone directive ইনজেক্ট করা যায়। A/AAAA `_is_ip` দিয়ে যাচাই হয়, বাকিগুলো নয়।
- **ফিক্স:** rtype অনুযায়ী value ভ্যালিডেট কর; newline/control char রিজেক্ট কর।

### - [ ] ৯. Mail injection পরিবার
- **ফাইল:** `app/providers/linux.py:619-622` (Sieve), `linux.py:562-586` (dovecot),
  `linux.py:606-608` (postfix virtual-alias)
- **সমস্যা:** autoresponder subject/body → Sieve ইনজেকশন; mailbox address traversal +
  dovecot line injection; forwarder src/dest → postfix alias ইনজেকশন। কোনোটাই যাচাই হয় না।
- **ফিক্স:** address regex + subject/body escape/encode কর।

### - [ ] ১০. php.ini pool key injection
- **ফাইল:** `app/providers/linux.py:105-110`
- **সমস্যা:** `_write_php_pool` value স্যানিটাইজ করে কিন্তু **key নয়** → কারসাজি key দিয়ে
  FPM pool কনফিগে ডিরেক্টিভ ইনজেক্ট।
- **ফিক্স:** key কে allowlist/regex দিয়ে যাচাই কর।

### - [ ] ১১. XFF দিয়ে login-throttle বাইপাস
- **ফাইল:** `app/security.py:31-33`
- **সমস্যা:** throttle client IP নেয় `X-Forwarded-For` থেকে বিশ্বাস করে → হেডার স্পুফ করে
  ৫-ফেইল লকআউট বাইপাস করে ব্রুট-ফোর্স।
- **ফিক্স:** শুধু trusted proxy থেকে XFF মানো, নইলে সরাসরি socket peer IP ব্যবহার কর।

---

## 🟡 MEDIUM

### - [ ] ১২. CSRF middleware fail-open + netloc-only
- **ফাইল:** `app/middleware.py:49-53`
- **সমস্যা:** Origin ও Referer **দুটোই অনুপস্থিত থাকলে** পাস করে (fail-open); শুধু netloc
  মেলায় (scheme উপেক্ষা করে)। প্রতি-ফর্ম CSRF টোকেন নেই (SameSite=Lax কিছুটা মিটিগেট করে)।
- **ফিক্স:** দুটোই অনুপস্থিত হলে রিজেক্ট; scheme+host দুটোই মেলাও; ভবিষ্যতে per-form token।

### - [ ] ১৩. কোনো CSP নেই
- **ফাইল:** `app/middleware.py:23-32`
- **সমস্যা:** Content-Security-Policy হেডার নেই → XSS হলে ডিফেন্স-ইন-ডেপথ নেই।
  (`X-XSS-Protection:0` ঠিক আছে।)
- **ফিক্স:** কড়া `default-src 'self'` CSP যোগ কর।

### - [ ] ১৪. Username enumeration timing oracle
- **ফাইল:** `app/security.py:86-90`
- **সমস্যা:** অস্তিত্বহীন ইউজারের জন্য PBKDF2 চলে না → টাইমিং পার্থক্যে ইউজারনেম আছে কিনা বোঝা যায়।
- **ফিক্স:** ইউজার না থাকলেও একটা dummy hash-এর বিরুদ্ধে verify চালাও (constant time)।

### - [ ] ১৫. দুর্বল PBKDF2 iteration
- **ফাইল:** `app/security.py:21`
- **সমস্যা:** `_ITERATIONS=200_000`, OWASP প্রস্তাবিত ~৬০০k এর নিচে।
- **ফিক্স:** `_ITERATIONS` ~600_000 এ বাড়াও।

### - [ ] ১৬. `int()` তে 500 এরর (robustness)
- **ফাইল:** `app/routers/node.py:137/200/223`, `app/routers/php.py:163/182/204/222/251`
- **সমস্যা:** ফর্ম ইনপুটে bare `int(domain_id)`/`int(app_id)` → অ-সংখ্যা দিলে ValueError → 500।
  (IDOR নয়, ownership পরে চেক হয়; শুধু আন-হ্যান্ডেলড ক্র্যাশ।)
- **ফিক্স:** try/except বা Pydantic/টাইপ্‌ড ফর্ম দিয়ে হ্যান্ডেল কর।

### - [ ] ১৭. Orphaned WordPress DB
- **ফাইল:** `app/routers/wordpress.py:257-283`
- **সমস্যা:** zip ডাউনলোডের **আগেই** Database row + আসল MySQL DB commit হয় → ডাউনলোড
  ব্যর্থ হলে DB অরফান থাকে (রিসোর্স লিক)।
- **ফিক্স:** ডাউনলোড সফল হওয়ার পর DB তৈরি কর, বা ব্যর্থতায় rollback কর।

### - [ ] ১৮. delete_domain এ ডেপথ-গার্ড ছাড়া rmtree
- **ফাইল:** `app/routers/domains.py:125-126`
- **সমস্যা:** `shutil.rmtree(Path(docroot).parent, ignore_errors=True)`, wordpress.py এর মত
  ডেপথ চেক (`<3`/`<4`) নেই → docroot কারসাজি হলে বড় ক্ষতির ঝুঁকি।
- **ফিক্স:** rmtree এর আগে path depth + prefix (`/var/www/...`) গার্ড যোগ কর।

### - [ ] ১৯. db_execute `_ident` স্কিপ
- **ফাইল:** `app/providers/linux.py:463-469`
- **সমস্যা:** db_execute path `_ident` ভ্যালিডেশন এড়িয়ে যায় (#৪ এর সাথে সম্পর্কিত)।
- **ফিক্স:** #৪ এর সাথে একসাথে ঠিক কর।

### - [ ] ২০. mysql escaping edge-case
- **ফাইল:** `app/providers/linux.py:42-44`
- **সমস্যা:** `_mysql_str` `NO_BACKSLASH_ESCAPES` মোডে ভাঙে।
- **ফিক্স:** parameterized/quoted literal ব্যবহার কর, বা sql_mode ধরে নিয়ো না।

---

## 🟢 LOW / Hardening

- [ ] **২১.** অ-অথেন্টিকেটেড malleable STREAM cipher — `app/crypto.py`; confidentiality-only
  (docstring স্বীকার করে), MAC নেই। → AEAD (যেমন authenticated tag) যোগ করার কথা ভাবো।
- [ ] **২২.** ৬-অক্ষরের দুর্বল পাসওয়ার্ড মিনিমাম — `app/routers/users.py:90`,
  `app/routers/wordpress.py:218`। → মিনিমাম বাড়াও (≥12)।
- [ ] **২৩.** WP admin পাসওয়ার্ড argv-তে → `/proc` এ দৃশ্যমান —
  `app/routers/wordpress.py:301` → `app/providers/linux.py:448`। → stdin দিয়ে পাস কর।
- [ ] **২৪.** DB-name enumeration লিক — `app/routers/databases.py:58`/`dbwizard.py:70`
  গ্লোবাল নাম-চেক আলাদা এররে অন্য টেন্যান্টের DB নাম ফাঁস করে। → জেনেরিক এরর দেখাও।
- [ ] **২৫.** `is_admin` কলাম default=True — `app/models.py:27`। **শোষণযোগ্য নয়**
  (create_user `users.py:102-104` ও bootstrap দুটোই is_admin স্পষ্ট সেট করে), তবু latent
  footgun। → `default=False` কর।
- [ ] **২৬.** JS onclick single-quote স্ট্রিং-এ raw ভ্যালু — `app/templates/node.html:119`
  (`domain.name`), `app/templates/dns.html:47` (`r.rtype`)। autoescape থাকায় ঝুঁকি কম,
  তবু JS-context এ ব্রেক করতে পারে। → JS-escape বা data-attribute ব্যবহার কর।

---

## ✅ যা যাচাই করে নিরাপদ পেয়েছি (বাগ নয়)

- **File Manager path traversal** — `files.py:51` `_safe_join` (`.resolve()` + parents চেক):
  traversal/symlink/absolute/null-byte সব ফেইল-ক্লোজড।
- **Zip-slip** — `files.py:643` `_safe_extract` নিরাপদ।
- **Backup download/delete** — owner mismatch → 404 (`backups.py:77/93`)।
- **কোনো IDOR নেই** — প্রতিটি per-resource হ্যান্ডলার `owner_id`/parent ownership ফিল্টার করে।
- **DB নাম ভ্যালিডেশন** — `_ident` + escaped literal (`linux.py:482-506`)।
- **`/packages` reseller access** — ইচ্ছাকৃত ডিজাইন, বাগ নয়।
- **কোনো `| safe` নেই / autoescape ON** — stored-XSS surface কম।

---

## অগ্রাধিকার সুপারিশ (কম effort-এ বড় ঝুঁকি কমায়)

1. **cron command (#১)** ও **backup restore (#৩)** — সাধারণ ইউজারের হাতে root RCE, আগে বন্ধ কর।
2. **SQL console (#৪)** — raw sql নির্বাচিত DB-তে scope কর, panel-admin socket বন্ধ কর।
3. **domain/fqdn + DNS/mail ফিল্ড (#৬,৮,৯)** — একটা কড়া regex ভ্যালিডেটর সব provider
   entry-point এ প্রয়োগ কর।
4. **SECRET_KEY ও ADMIN_PASSWORD (#৫,৭)** — env বাধ্যতামূলক; না থাকলে স্টার্টআপে ব্যর্থ হও।

---

## আলাদা বিষয় (এই স্ট্যাটিক অডিটের বাইরে)

আগের লাইভ-ক্রলে `/node` অ্যাডমিন 500 পাওয়া গেছে — কারণ live DB-তে `c3a5d8e21f47`
migration চালানো হয়নি → `node_apps` টেবিল নেই। ফিক্স:

```bash
alembic upgrade head && sudo systemctl restart litespanel
```

(এখনো নিশ্চিত করা হয়নি।)

