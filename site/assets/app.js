// ipssl.cc landing page: hostname converter, live DNS check, language switch.
// The parser mirrors src/parse.rs, so the page answers the way the server does.
(() => {
  "use strict";

  const ZONE = "ipssl.cc";
  const DOH = "https://cloudflare-dns.com/dns-query";
  const CHECK_TIMEOUT_MS = 8000;

  // ---------------------------------------------------------------------
  // Parsing, ported from src/parse.rs. An address is { v: 4 | 6, a: [...] }
  // with four octets or eight 16-bit groups.

  /** A decimal octet, 0-255, without leading zeros. */
  const octet = (s) => (/^(0|[1-9]\d{0,2})$/.test(s) && +s <= 255 ? +s : null);

  /** Eight hex digits, e.g. 0a000001 for 10.0.0.1. */
  const hexV4 = (s) =>
    /^[0-9a-f]{8}$/.test(s) ? [0, 2, 4, 6].map((i) => parseInt(s.slice(i, i + 2), 16)) : null;

  const allOctets = (parts) => {
    const o = parts.map(octet);
    return o.every((x) => x !== null) ? o : null;
  };

  /** a.b.c.d across four labels; the first label may carry a prefix (app-10.0.0.1). */
  const dottedV4 = (parts) => allOctets([parts[0].split("-").pop(), parts[1], parts[2], parts[3]]);

  /**
   * IPv6 text to eight groups, with the same rules as Rust's Ipv6Addr parser:
   * at most one "::", and it must stand for at least one group. An IPv4 tail
   * (::ffff:1.2.3.4) is only accepted for typed input, never inside a label.
   */
  function parseV6(s, allowV4Tail) {
    const halves = s.split("::");
    if (halves.length > 2) return null;
    const groups = (part, isTail) => {
      if (part === "") return [];
      const items = part.split(":");
      const out = [];
      for (let i = 0; i < items.length; i++) {
        const g = items[i];
        if (allowV4Tail && isTail && i === items.length - 1 && g.includes(".")) {
          const v4 = allOctets(g.split("."));
          if (!v4 || v4.length !== 4) return null;
          out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
        } else if (/^[0-9a-f]{1,4}$/.test(g)) {
          out.push(parseInt(g, 16));
        } else {
          return null;
        }
      }
      return out;
    };
    if (halves.length === 1) {
      const all = groups(s, true);
      return all && all.length === 8 ? all : null;
    }
    const head = groups(halves[0], false);
    const tail = groups(halves[1], true);
    if (!head || !tail || head.length + tail.length > 7) return null;
    return [...head, ...Array(8 - head.length - tail.length).fill(0), ...tail];
  }

  /** An address inside one label: dashed IPv6, dashed IPv4 or eight hex digits. */
  function singleLabel(label) {
    if (label.includes("-")) {
      const v6 = parseV6(label.replace(/-/g, ":"), false);
      if (v6) return { v: 6, a: v6 };
    }
    const t = label.split("-");
    for (let end = t.length - 1; end >= 0; end--) {
      if (end >= 3) {
        const o = allOctets(t.slice(end - 3, end + 1));
        if (o) return { v: 4, a: o };
      }
      const h = hexV4(t[end]);
      if (h) return { v: 4, a: h };
    }
    return null;
  }

  /** Labels left of the zone, in normal order. The rightmost address wins. */
  function extractIp(labels) {
    for (let end = labels.length - 1; end >= 0; end--) {
      if (end >= 3) {
        const o = dottedV4(labels.slice(end - 3, end + 1));
        if (o) return { v: 4, a: o };
      }
      const ip = singleLabel(labels[end]);
      if (ip) return ip;
    }
    return null;
  }

  // ---------------------------------------------------------------------
  // Formatting

  /** RFC 5952 text: lowercase, longest run of two or more zero groups as "::". */
  function v6Text(a) {
    let best = -1;
    let bestLen = 0;
    for (let i = 0; i < 8; ) {
      if (a[i] !== 0) {
        i++;
        continue;
      }
      let j = i;
      while (j < 8 && a[j] === 0) j++;
      if (j - i > bestLen) {
        best = i;
        bestLen = j - i;
      }
      i = j;
    }
    const hex = a.map((g) => g.toString(16));
    if (bestLen < 2) return hex.join(":");
    return `${hex.slice(0, best).join(":")}::${hex.slice(best + bestLen).join(":")}`;
  }

  const ipText = (ip) => (ip.v === 4 ? ip.a.join(".") : v6Text(ip.a));

  /**
   * IPv6 as one label. A label may not start or end with "-", so a leading
   * or trailing "::" gets an explicit zero group (::1 becomes 0--1).
   */
  function v6Label(a) {
    let t = v6Text(a);
    if (t.startsWith("::")) t = `0${t}`;
    if (t.endsWith("::")) t += "0";
    return t.replace(/:/g, "-");
  }

  /** Every name the page suggests for an address, recommended first. */
  function namesFor(ip) {
    const z = `.${ZONE}`;
    if (ip.v === 4) {
      const dashed = ip.a.join("-");
      const hex = ip.a.map((o) => o.toString(16).padStart(2, "0")).join("");
      return [
        { pre: "", addr: dashed, tag: "rec" },
        { pre: "app-", addr: dashed, tag: "label" },
        { pre: "", addr: ip.a.join("."), tag: "dotted" },
        { pre: "", addr: hex, tag: "hex" },
      ].map((n) => ({ ...n, zone: z }));
    }
    const label = v6Label(ip.a);
    const full = ip.a.map((g) => g.toString(16)).join("-");
    const names = [
      { pre: "", addr: label, tag: "rec" },
      { pre: "app.", addr: label, tag: "sub" },
    ];
    if (full !== label) names.push({ pre: "", addr: full, tag: "expanded" });
    return names.map((n) => ({ ...n, zone: z }));
  }

  const nameText = (n) => n.pre + n.addr + n.zone;

  /** Where an address can be used: public, private, documentation, other. */
  function kindOf(ip) {
    const a = ip.a;
    if (ip.v === 4) {
      const [x, y, z] = a;
      if (x === 10 || x === 127 || (x === 172 && y >= 16 && y <= 31) || (x === 192 && y === 168)) return "private";
      if ((x === 169 && y === 254) || (x === 100 && y >= 64 && y <= 127)) return "private";
      if ((x === 192 && y === 0 && z === 2) || (x === 198 && y === 51 && z === 100) || (x === 203 && y === 0 && z === 113)) return "doc";
      if (x === 0 || x >= 224 || (x === 198 && (y === 18 || y === 19))) return "other";
      return "public";
    }
    const g0 = a[0];
    if (a.slice(0, 7).every((g) => g === 0) && a[7] === 1) return "private"; // ::1
    if ((g0 & 0xfe00) === 0xfc00 || (g0 & 0xffc0) === 0xfe80) return "private";
    if (g0 === 0x2001 && a[1] === 0x0db8) return "doc";
    if (g0 >= 0x2000 && g0 <= 0x3fff) return "public";
    return "other";
  }

  // ---------------------------------------------------------------------
  // Strings for the parts of the page that JavaScript writes.

  const STR = {
    en: {
      title: "ipssl.cc · Wildcard DNS for any IP address",
      desc: "Free wildcard DNS: 10-0-0-1.ipssl.cc resolves to 10.0.0.1. IPv4 and IPv6, no sign-up, and HTTPS certificates from any ACME CA. Open source, written in Rust.",
      langBtn: "中文",
      langAria: "切换到中文",
      empty: "Type an IP address such as 10.0.0.1, or a name such as app.10-0-0-1.ipssl.cc.",
      invalid: "That is not an IP address or a hostname.",
      zoneId: "Drop the zone index (%…); a name cannot carry it.",
      none: "No IP address in this name, so ipssl.cc answers NXDOMAIN.",
      found: "{name} resolves to {ip}.",
      "kind.public": "Public address. A certificate for these names can be issued to the server at this address.",
      "kind.private": "Private address. It resolves, but a CA cannot reach it, and some routers drop the answer.",
      "kind.doc": "Documentation address, reserved for examples.",
      "kind.other": "Not a public unicast address.",
      "tag.rec": "Recommended",
      "tag.label": "With a label",
      "tag.dotted": "Dotted",
      "tag.hex": "Hex",
      "tag.sub": "Subdomain",
      "tag.expanded": "Expanded",
      copy: "Copy",
      copied: "Copied",
      copyCmd: "Copy command",
      copyInstall: "Copy install command",
      checking: "Asking Cloudflare DNS…",
      match: "Resolves correctly",
      mismatch: "Expected {want}",
      nx: "NXDOMAIN: the name does not exist.",
      nodata: "No {type} record for this name.",
      error: "Could not reach Cloudflare DNS. Try dig +short {name} instead.",
      ttl: "TTL {ttl}s",
      "snip.public": "Uses the first name from the converter. Run it on the server at {ip}.",
      "snip.doc": "Uses the first name from the converter. Run it on the server that owns the address.",
      "snip.private": "{ip} is private, so a CA cannot reach it. Certificates need a public address.",
      "snip.other": "{ip} is not a public address, so a CA cannot reach it.",
    },
    zh: {
      title: "ipssl.cc · 任意 IP 的通配符 DNS",
      desc: "免费的通配符 DNS：10-0-0-1.ipssl.cc 解析到 10.0.0.1。支持 IPv4 和 IPv6，无需注册，可用任意 ACME CA 签发 HTTPS 证书。开源，用 Rust 编写。",
      langBtn: "EN",
      langAria: "Switch to English",
      empty: "输入一个 IP 地址，比如 10.0.0.1，或者一个域名，比如 app.10-0-0-1.ipssl.cc。",
      invalid: "这不是 IP 地址，也不是域名。",
      zoneId: "去掉接口标识（%…），域名里放不下它。",
      none: "这个名字里没有 IP 地址，ipssl.cc 会返回 NXDOMAIN。",
      found: "{name} 解析到 {ip}。",
      "kind.public": "公网地址。这台服务器可以为这些域名申请证书。",
      "kind.private": "私有地址。可以正常解析，但 CA 访问不到，有些路由器还会丢弃这类应答。",
      "kind.doc": "文档示例地址，只用于举例。",
      "kind.other": "不是公网单播地址。",
      "tag.rec": "推荐",
      "tag.label": "带前缀",
      "tag.dotted": "点分",
      "tag.hex": "十六进制",
      "tag.sub": "子域名",
      "tag.expanded": "完整写法",
      copy: "复制",
      copied: "已复制",
      copyCmd: "复制命令",
      copyInstall: "复制安装命令",
      checking: "正在查询 Cloudflare DNS…",
      match: "解析正确",
      mismatch: "预期是 {want}",
      nx: "NXDOMAIN：这个名字不存在。",
      nodata: "这个名字没有 {type} 记录。",
      error: "连不上 Cloudflare DNS，可以改用 dig +short {name} 查询。",
      ttl: "TTL {ttl} 秒",
      "snip.public": "使用转换器里的第一个域名，在 {ip} 这台服务器上运行。",
      "snip.doc": "使用转换器里的第一个域名，在拥有这个地址的服务器上运行。",
      "snip.private": "{ip} 是私有地址，CA 访问不到。申请证书需要公网地址。",
      "snip.other": "{ip} 不是公网地址，CA 访问不到。",
    },
  };

  // Translations of the static page. English lives in the HTML itself.
  const ZH = {
    skip: "跳到正文",
    "nav.names": "命名规则",
    "nav.https": "HTTPS",
    "nav.servers": "服务器",
    "nav.faq": "常见问题",
    "hero.t1": "每个 IP 地址，",
    "hero.t2": "都已经有了域名。",
    "hero.lead": "把 IP 地址写进 <code>ipssl.cc</code> 下的域名，它就解析到这个地址。免费，支持 IPv4 和 IPv6，无需注册，还能用任意 ACME CA 签发 HTTPS 证书。",
    "hero.source": "查看源代码",
    "hero.how": "了解命名规则",
    "tool.label": "IP 地址或域名",
    "tool.try": "试试",
    "tool.check": "实时查询",
    "tool.checkNote": "通过 Cloudflare 的公共 DNS over HTTPS 查询第一个域名。",
    "trace.browser": "浏览器",
    "names.title": "把地址写进域名。",
    "names.lead": "点写成横杠，整个地址就放进了一级标签。地址前面的部分随你起名。",
    "anat.label": "你的前缀，可省略",
    "anat.addr": "地址，点写成横杠",
    "anat.zone": "域名后缀",
    "anat.result": "解析结果",
    "forms.name": "域名",
    "forms.result": "解析到",
    "forms.notes": "说明",
    "forms.n1": "<strong>推荐。</strong>只有一级标签，最容易申请证书",
    "forms.n2": "地址前后可以加词，用 <code>-</code> 连接",
    "forms.n3": "子域名层级不限",
    "forms.n4": "点分写法",
    "forms.n5": "八位十六进制",
    "forms.n6": "IPv6：<code>:</code> 写成 <code>-</code>，<code>::</code> 写成 <code>--</code>",
    "forms.n7": "IPv6 地址前面的词要单独放一级标签",
    "rules.title": "规则",
    "rules.r1": "一个名字里有多个地址时，以最右边、最靠近域名后缀的那个为准。",
    "rules.r2": "带前导零的数字（如 <code>010</code>）会被拒绝，免得有人猜它是不是八进制。",
    "rules.r3": "对 IPv4 名字查 AAAA（反过来也一样）会得到空应答，而不是 NXDOMAIN。",
    "rules.r4": "查询 <code>ip.ipssl.cc</code> 的 TXT 记录，返回查询的来源地址，通常是你的解析器。",
    "https.title": "正规证书，签发给你自己的服务器。",
    "https.lead": "域名解析到你的服务器，所以在服务器上运行 ACME 客户端，就能像普通域名一样通过 HTTP-01 或 TLS-ALPN-01 验证。无需注册，私钥也不会离开你的机器。",
    "https.n1": "<strong>任意 CA。</strong>这个域没有 CAA 记录，Let's Encrypt、ZeroSSL、Google Trust Services 等都能签发。",
    "https.n2": "<strong>只限公网地址。</strong>CA 要能访问到你的服务器，所以 <code>192.168.1.10</code> 这类私有地址无法验证。",
    "https.n3": "<strong>共用一份额度。</strong>ipssl.cc 下的所有名字共用 Let's Encrypt 按注册域名计算的签发限额。遇到限额可以稍后再试，或者换一家 CA。",
    "servers.title": "由三台权威服务器应答，分布在三个地区。",
    "servers.lead": "每台都在 IPv4 和 IPv6 上通过 UDP 和 TCP 的 53 端口应答，运行同一份开源服务端。",
    "region.tokyo": "东京",
    "region.us": "美国",
    "region.hk": "香港",
    "facts.rl.t": "限速，但不会断",
    "facts.rl.d": "UDP 应答按客户端网段限速，服务器不会被拿去攻击别人。收到截断应答的解析器会改用 TCP 重试，TCP 不限速。",
    "facts.log.t": "不记录查询",
    "facts.log.d": "服务器只保留汇总计数，比如回答了多少次 A 查询，不记录查询的名字和客户端地址。",
    "facts.rust.t": "小巧，用 Rust 编写",
    "facts.rust.d": "基于 hickory-dns 的权威服务器。修改配置后热加载，不丢任何一个查询。",
    "faq.title": "常见问题",
    "faq.lead": "没找到答案？到 <a href=\"https://github.com/gonolab/ipssl.cc/issues\">issue 区</a>提问。",
    "faq.q1": "为什么私有地址在我的网络里解析不出来？",
    "faq.a1": "很多路由器（OpenWrt、pfSense、dnsmasq、Fritz!Box 等）开启了 DNS 重绑定保护，会丢弃指向私有地址的应答。在路由器里把 <code>ipssl.cc</code> 加入白名单，或者改用公共解析器。",
    "faq.q2": "能下载 ipssl.cc 的通配符证书吗？",
    "faq.a2": "不能。公开私钥违反 CA 的订户协议，而且任何拿到私钥的人都能吊销证书。请在自己的服务器上申请证书，只需要一条命令。",
    "faq.q3": "为什么 ipssl.cc 不在公共后缀列表（PSL）里？",
    "faq.a3": "PSL 明确不收录把域名里的 IP 解析到该 IP 的服务：同一个 IP 会在不同时间分配给不同的人，不能证明对域名的稳定控制。DNS 解析不依赖 PSL。",
    "faq.q4": "怎么查看我的 DNS 查询是从哪里发出的？",
    "faq.a4": "运行 <code>dig +short TXT ip.ipssl.cc</code>，返回的是查询到达我们时的来源地址，通常是你的递归解析器。",
    "faq.q5": "可以给自己的域名部署一套吗？",
    "faq.a5": "可以。服务端以 MIT 协议开源，用下面的安装脚本就能装到任何 Linux 服务器上。配置和注册商设置见 README。",
    "faq.q6": "怎么举报滥用？",
    "faq.a6": "在 <a href=\"https://github.com/gonolab/ipssl.cc/issues\">GitHub</a> 上提交 issue，写明域名和它的用途。服务端支持屏蔽列表，用于滥用的名字可以停止解析。",
    "cta.title": "为你自己的域名部署一套。",
    "cta.lead": "安装脚本会下载静态编译的 Linux 程序，对照发布的校验和检查后，配置好 systemd 服务。",
    "cta.github": "在 GitHub 上查看",
    "cta.issue": "提交 issue",
    "footer.license": "MIT 协议",
    "footer.abuse": "举报滥用",
  };

  // ---------------------------------------------------------------------
  // Page state

  const $ = (sel) => document.querySelector(sel);
  const input = $("#ip-input");
  const status = $("#tool-status");
  const results = $("#results");
  const checkBtn = $("#check-btn");
  const trace = $("#trace");
  const answer = $("#answer");
  const snipNote = $("#snip-note");

  const i18nNodes = [...document.querySelectorAll("[data-i18n]")];
  const EN = Object.fromEntries(i18nNodes.map((n) => [n.dataset.i18n, n.innerHTML]));

  let lang = "en";
  let current = null; // { ip, names, kind, source }
  let checkSeq = 0;

  const t = (key, vars = {}) =>
    (STR[lang][key] ?? STR.en[key] ?? key).replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? "");

  const escapeHtml = (s) =>
    String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

  const ICON_COPY = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/></svg>';
  const ICON_CHECK = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5 9.5 17 19 7.5"/></svg>';
  const ICON_X = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M7 7l10 10M17 7 7 17"/></svg>';

  /** Reads the input: an IP address, or a hostname to run through the parser. */
  function readInput(raw) {
    const s = raw.trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
    if (!s) return { state: "empty" };
    if (s.includes(":")) {
      if (s.includes("%")) return { state: "error", msg: "zoneId" };
      const a = parseV6(s, true);
      return a ? { state: "ip", ip: { v: 6, a } } : { state: "error", msg: "invalid" };
    }
    if (/^\d+(\.\d+){3}$/.test(s)) {
      const a = allOctets(s.split("."));
      if (a) return { state: "ip", ip: { v: 4, a } };
    }
    if (!/^[a-z0-9.-]+$/.test(s) || s.split(".").some((l) => l === "")) return { state: "error", msg: "invalid" };
    const name = s.endsWith(`.${ZONE}`) ? s : `${s}.${ZONE}`;
    const labels = s === ZONE ? [] : s.endsWith(`.${ZONE}`) ? s.slice(0, -ZONE.length - 1).split(".") : s.split(".");
    const ip = extractIp(labels);
    return ip ? { state: "name", ip, name } : { state: "none", name };
  }

  function renderStatus(r) {
    status.dataset.kind = "";
    input.removeAttribute("aria-invalid");
    if (r.state === "empty") {
      status.textContent = t("empty");
    } else if (r.state === "error") {
      status.dataset.kind = "error";
      status.textContent = t(r.msg);
      input.setAttribute("aria-invalid", "true");
    } else if (r.state === "none") {
      status.dataset.kind = "error";
      status.textContent = t("none");
    } else {
      const kind = kindOf(r.ip);
      status.dataset.kind = kind;
      const lead = r.state === "name" ? `${escapeHtml(t("found", { name: r.name, ip: ipText(r.ip) }))} ` : "";
      status.innerHTML = `<strong>IPv${r.ip.v}</strong>${lead}${escapeHtml(t(`kind.${kind}`))}`;
    }
  }

  function renderNames() {
    if (!current) {
      results.innerHTML = "";
      return;
    }
    results.innerHTML = current.names
      .map((n) => {
        const text = nameText(n);
        const pre = n.pre ? `<span class="p">${escapeHtml(n.pre)}</span>` : "";
        return `<li><span class="host">${pre}<span class="a">${escapeHtml(n.addr)}</span><span class="z">${escapeHtml(n.zone)}</span></span><span class="tag${n.tag === "rec" ? " rec" : ""}">${escapeHtml(t(`tag.${n.tag}`))}</span><button class="copy" type="button" data-copy="${escapeHtml(text)}" aria-label="${escapeHtml(`${t("copy")} ${text}`)}">${ICON_COPY}</button></li>`;
      })
      .join("");
  }

  /** The anatomy figure and the certificate snippets follow the converter. */
  function renderElsewhere() {
    const ip = current ? current.ip : { v: 4, a: [203, 0, 113, 10] };
    const rec = current ? current.names[0] : namesFor(ip)[0];
    const kind = kindOf(ip);
    $("#anat-label").textContent = ip.v === 4 ? "app-" : "app.";
    $("#anat-addr").textContent = rec.addr;
    $("#anat-ip").textContent = ipText(ip);
    document.querySelectorAll(".host-slot").forEach((el) => {
      el.textContent = nameText(rec);
    });
    snipNote.dataset.kind = kind;
    snipNote.textContent = t(`snip.${kind}`, { ip: ipText(ip) });
  }

  function update() {
    const r = readInput(input.value);
    current = r.ip ? { ip: r.ip, names: namesFor(r.ip), kind: kindOf(r.ip) } : null;
    renderStatus(r);
    renderNames();
    renderElsewhere();
    checkBtn.disabled = !current;
    // A new input makes an earlier check result stale.
    checkSeq++;
    trace.hidden = true;
    trace.dataset.state = "idle";
    answer.textContent = "";
  }

  // ---------------------------------------------------------------------
  // Live check over DNS-over-HTTPS (JSON API). Only the name is sent.

  async function check() {
    if (!current) return;
    const seq = ++checkSeq;
    const name = nameText(current.names[0]);
    const type = current.ip.v === 4 ? "A" : "AAAA";
    const want = ipText(current.ip);
    trace.hidden = false;
    trace.dataset.state = "run";
    answer.dataset.state = "";
    answer.textContent = t("checking");
    checkBtn.disabled = true;

    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), CHECK_TIMEOUT_MS);
    try {
      const url = `${DOH}?name=${encodeURIComponent(name)}&type=${type}`;
      const res = await fetch(url, { headers: { accept: "application/dns-json" }, signal: ctl.signal, cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      if (seq !== checkSeq) return;
      const code = type === "A" ? 1 : 28;
      const records = (body.Answer || []).filter((rr) => rr.type === code);
      if (body.Status === 3) {
        finish("bad", escapeHtml(t("nx")));
      } else if (!records.length) {
        finish("bad", escapeHtml(t("nodata", { type })));
      } else {
        const norm = (d) => (type === "A" ? d : ipText({ v: 6, a: parseV6(d, true) || [] }));
        const got = records.map((rr) => norm(rr.data));
        const ok = got.includes(want);
        const shown = got.map((g) => `<code>${type} ${escapeHtml(g)}</code>`).join(" ");
        const verdict = ok
          ? `<span class="verdict">${ICON_CHECK}${escapeHtml(t("match"))}</span>`
          : `<span class="verdict">${ICON_X}${escapeHtml(t("mismatch", { want }))}</span>`;
        finish(ok ? "ok" : "bad", `${shown}<span>${escapeHtml(t("ttl", { ttl: records[0].TTL }))}</span>${verdict}`);
      }
    } catch (err) {
      if (seq === checkSeq) finish("bad", escapeHtml(t("error", { name })));
    } finally {
      clearTimeout(timer);
      if (seq === checkSeq) checkBtn.disabled = false;
    }

    function finish(state, html) {
      trace.dataset.state = state;
      answer.dataset.state = state;
      answer.innerHTML = html;
    }
  }

  // ---------------------------------------------------------------------
  // Copy buttons

  async function copyText(text, btn) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Fallback for browsers without the async clipboard API.
      const area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.append(area);
      area.select();
      try {
        document.execCommand("copy");
      } catch {
        /* nothing else to try */
      }
      area.remove();
    }
    const label = btn.getAttribute("aria-label");
    btn.dataset.copied = "";
    btn.innerHTML = ICON_CHECK;
    btn.setAttribute("aria-label", t("copied"));
    setTimeout(() => {
      delete btn.dataset.copied;
      btn.innerHTML = ICON_COPY;
      btn.setAttribute("aria-label", label);
    }, 1400);
  }

  results.addEventListener("click", (e) => {
    const btn = e.target.closest(".copy");
    if (btn) copyText(btn.dataset.copy, btn);
  });

  $("#snip-copy").addEventListener("click", (e) => {
    const panel = document.querySelector(".snip:not([hidden]) code");
    // Leave out the prompt and the file-name comment.
    const text = [...panel.childNodes]
      .filter((n) => !(n.nodeType === 1 && n.matches(".prompt, .comment")))
      .map((n) => n.textContent)
      .join("")
      .replace(/^\n/, "");
    copyText(text, e.currentTarget);
  });

  $("#install-copy").addEventListener("click", (e) => {
    copyText($("#install-cmd").textContent, e.currentTarget);
  });

  // ---------------------------------------------------------------------
  // Tabs (certbot / acme.sh / Caddy), with arrow-key navigation.

  const tabs = [...document.querySelectorAll('[role="tab"]')];
  function selectTab(tab, focus) {
    tabs.forEach((other) => {
      const on = other === tab;
      other.setAttribute("aria-selected", String(on));
      other.tabIndex = on ? 0 : -1;
      document.getElementById(other.getAttribute("aria-controls")).hidden = !on;
    });
    if (focus) tab.focus();
  }
  tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => selectTab(tab, false));
    tab.addEventListener("keydown", (e) => {
      const step = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
      if (step) {
        e.preventDefault();
        selectTab(tabs[(i + step + tabs.length) % tabs.length], true);
      } else if (e.key === "Home" || e.key === "End") {
        e.preventDefault();
        selectTab(tabs[e.key === "Home" ? 0 : tabs.length - 1], true);
      }
    });
  });

  // ---------------------------------------------------------------------
  // Language

  const langBtn = $("#lang-toggle");
  function setLang(next, save) {
    lang = next;
    const dict = lang === "zh" ? ZH : EN;
    i18nNodes.forEach((n) => {
      const html = dict[n.dataset.i18n] ?? EN[n.dataset.i18n];
      if (html !== undefined) n.innerHTML = html;
    });
    document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
    document.title = t("title");
    document.querySelector('meta[name="description"]').setAttribute("content", t("desc"));
    langBtn.textContent = t("langBtn");
    langBtn.setAttribute("aria-label", t("langAria"));
    langBtn.lang = lang === "zh" ? "en" : "zh-CN";
    $("#snip-copy").setAttribute("aria-label", t("copyCmd"));
    $("#install-copy").setAttribute("aria-label", t("copyInstall"));
    if (save) {
      try {
        localStorage.setItem("lang", lang);
      } catch {
        /* storage may be blocked; the choice just won't be remembered */
      }
    }
    update();
  }

  langBtn.addEventListener("click", () => setLang(lang === "zh" ? "en" : "zh", true));

  // ---------------------------------------------------------------------
  // Wire up

  input.addEventListener("input", update);
  checkBtn.addEventListener("click", check);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") check();
  });
  document.querySelectorAll("[data-example]").forEach((btn) => {
    btn.addEventListener("click", () => {
      input.value = btn.dataset.example;
      update();
      input.focus();
    });
  });

  let saved = null;
  try {
    saved = localStorage.getItem("lang");
  } catch {
    /* ignore */
  }
  setLang(saved === "zh" ? "zh" : "en", false);
})();
