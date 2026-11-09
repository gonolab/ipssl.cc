// ipssl.cc landing page: the address bar, live DNS check, certificate paths, language switch.
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
  // Where the address sits inside a typed hostname, for coloring its parts.
  // Mirrors extractIp, but reports character offsets instead of the value.

  /** The address inside one label, as [start, stop) offsets, or null. */
  function labelSpan(label) {
    if (label.includes("-") && parseV6(label.replace(/-/g, ":"), false)) return [0, label.length];
    const t = label.split("-");
    const offs = [];
    let p = 0;
    for (const tok of t) {
      offs.push(p);
      p += tok.length + 1;
    }
    for (let end = t.length - 1; end >= 0; end--) {
      if (end >= 3 && allOctets(t.slice(end - 3, end + 1))) return [offs[end - 3], offs[end] + t[end].length];
      if (hexV4(t[end])) return [offs[end], offs[end] + t[end].length];
    }
    return null;
  }

  /** [start, stop) of the address within labels.join("."), or null. */
  function addressSpan(labels) {
    const starts = [];
    let p = 0;
    for (const l of labels) {
      starts.push(p);
      p += l.length + 1;
    }
    for (let end = labels.length - 1; end >= 0; end--) {
      if (end >= 3 && dottedV4(labels.slice(end - 3, end + 1))) {
        const first = labels[end - 3];
        return [starts[end - 3] + first.lastIndexOf("-") + 1, starts[end] + labels[end].length];
      }
      const span = labelSpan(labels[end]);
      if (span) return [starts[end] + span[0], starts[end] + span[1]];
    }
    return null;
  }

  // ---------------------------------------------------------------------
  // Strings for the parts of the page that JavaScript writes.

  const STR = {
    en: {
      title: "ipssl.cc · A name and an SSL certificate for any IP address",
      desc: "Free wildcard DNS: 192-168-1-10.ipssl.cc resolves to 192.168.1.10, and the name can get a real SSL certificate from Let's Encrypt or any ACME CA, private addresses included. IPv4 and IPv6, no sign-up. Open source, written in Rust.",
      langBtn: "中文",
      langAria: "切换到中文",
      empty: "Type an IP address such as 10.0.2.2, or a name such as app.10-0-2-2.ipssl.cc.",
      invalid: "Use digits, letters, dots and dashes, as in 10.0.2.2 or app.10-0-2-2.ipssl.cc.",
      zoneId: "Drop the zone index (%…); a name cannot carry it.",
      found: "{name} resolves to {ip}.",
      "name.resolves": "Resolves to {ip}",
      "name.pending": "Press Enter to turn it into a name",
      "name.noneTitle": "No IP address in this name",
      "name.none": "ipssl.cc answers NXDOMAIN for it. Put an address in it, such as app.10-0-2-2.ipssl.cc.",
      "name.errorTitle": "Not an IP address or a hostname",
      "name.emptyTitle": "Type an IP address",
      "kind.public": "Public address. No DNS server of your own, nothing to register.",
      "kind.private": "Private address. Nothing to set up, though some routers block answers like this one.",
      "kind.doc": "Documentation address, reserved for examples.",
      "kind.other": "Not a public unicast address.",
      "cert.public": "Run one command on the server at {ip}, and Let's Encrypt or any other CA issues it.",
      "cert.doc": "Run one command on the server that owns the address, and any CA issues it.",
      "cert.private": "A CA cannot reach {ip}, so ipssl.cc proves the name through DNS for you. Get it from any machine.",
      "cert.other": "No CA issues certificates for {ip}.",
      "cert.none": "Put an IP address in the name to get a certificate for it.",
      "ai.prompt": "Read https://ipssl.cc/llms.txt, then give my machine at {ip} a hostname under ipssl.cc and an SSL certificate for it.",
      "ai.promptNoIp": "Read https://ipssl.cc/llms.txt, then give my machine a hostname under ipssl.cc and an SSL certificate for it.",
      "forms.caption": "Every way to write {ip}",
      "form.rec": "<strong>Recommended.</strong> One label, easiest to get certificates for",
      "form.words": "Words before or after the address, joined with <code>-</code>",
      "form.sub": "Any number of subdomain levels",
      "form.dotted": "Dotted form",
      "form.hex": "Eight hex digits",
      "form.v6": "<strong>Recommended.</strong> <code>:</code> written as <code>-</code>, <code>::</code> as <code>--</code>",
      "form.v6words": "Words in front of an IPv6 address go in their own label",
      "form.v6full": "Every group written out",
      "note.public": "Run it on the server at {ip}.",
      "note.doc": "Run it on the server that owns the address.",
      "note.publicEx": "Example name. Type a public IP above to use yours.",
      "note.private": "Run it on any machine with internet access.",
      "note.privateEx": "Example name. Type a private IP above to use yours.",
      copy: "Copy",
      copied: "Copied",
      copyName: "Copy {name}",
      copyPrompt: "Copy prompt",
      copyCmd: "Copy command",
      copyInstall: "Copy install command",
      checking: "Asking Cloudflare DNS…",
      match: "Resolves correctly",
      mismatch: "Expected {want}",
      nx: "NXDOMAIN: the name does not exist.",
      nodata: "No {type} record for this name.",
      error: "Could not reach Cloudflare DNS. Try dig +short {name} instead.",
      ttl: "TTL {ttl}s",
    },
    zh: {
      title: "ipssl.cc · 任意 IP 的域名和 SSL 证书",
      desc: "免费的通配符 DNS：192-168-1-10.ipssl.cc 解析到 192.168.1.10，这个域名还能从 Let's Encrypt 等任意 ACME CA 申请正规 SSL 证书，内网地址也可以。支持 IPv4 和 IPv6，无需注册。开源，用 Rust 编写。",
      langBtn: "EN",
      langAria: "Switch to English",
      empty: "输入一个 IP 地址，比如 10.0.2.2，或者一个域名，比如 app.10-0-2-2.ipssl.cc。",
      invalid: "只能用数字、字母、点和横杠，比如 10.0.2.2 或 app.10-0-2-2.ipssl.cc。",
      zoneId: "去掉接口标识（%…），域名里放不下它。",
      found: "{name} 解析到 {ip}。",
      "name.resolves": "解析到 {ip}",
      "name.pending": "按回车把它变成域名",
      "name.noneTitle": "这个名字里没有 IP 地址",
      "name.none": "ipssl.cc 会返回 NXDOMAIN。在名字里放一个地址，比如 app.10-0-2-2.ipssl.cc。",
      "name.errorTitle": "这不是 IP 地址，也不是域名",
      "name.emptyTitle": "输入一个 IP 地址",
      "kind.public": "公网地址。不用自己搭 DNS，也不用注册。",
      "kind.private": "私有地址。不用任何设置，但有些路由器会拦截这类应答。",
      "kind.doc": "文档示例地址，只用于举例。",
      "kind.other": "不是公网单播地址。",
      "cert.public": "在 {ip} 这台服务器上运行一条命令，Let's Encrypt 等任意 CA 都能签发。",
      "cert.doc": "在拥有这个地址的服务器上运行一条命令，任意 CA 都能签发。",
      "cert.private": "CA 访问不到 {ip}，由 ipssl.cc 通过 DNS 替你完成验证，在任意机器上都能申请。",
      "cert.other": "{ip} 这类地址申请不到证书。",
      "cert.none": "名字里要有 IP 地址，才能为它申请证书。",
      "ai.prompt": "请阅读 https://ipssl.cc/llms.txt，然后给 IP 为 {ip} 的机器配一个 ipssl.cc 域名，并为它申请 SSL 证书。",
      "ai.promptNoIp": "请阅读 https://ipssl.cc/llms.txt，然后给我的机器配一个 ipssl.cc 域名，并为它申请 SSL 证书。",
      "forms.caption": "{ip} 的所有写法",
      "form.rec": "<strong>推荐。</strong>只有一级标签，最容易申请证书",
      "form.words": "地址前后可以加词，用 <code>-</code> 连接",
      "form.sub": "子域名层级不限",
      "form.dotted": "点分写法",
      "form.hex": "八位十六进制",
      "form.v6": "<strong>推荐。</strong><code>:</code> 写成 <code>-</code>，<code>::</code> 写成 <code>--</code>",
      "form.v6words": "IPv6 地址前面的词要单独放一级标签",
      "form.v6full": "每一组都完整写出",
      "note.public": "在 {ip} 这台服务器上运行。",
      "note.doc": "在拥有这个地址的服务器上运行。",
      "note.publicEx": "示例域名。在上面输入公网 IP，就会换成你的。",
      "note.private": "在任意一台能上网的机器上运行。",
      "note.privateEx": "示例域名。在上面输入内网 IP，就会换成你的。",
      copy: "复制",
      copied: "已复制",
      copyName: "复制 {name}",
      copyPrompt: "复制提示词",
      copyCmd: "复制命令",
      copyInstall: "复制安装命令",
      checking: "正在查询 Cloudflare DNS…",
      match: "解析正确",
      mismatch: "预期是 {want}",
      nx: "NXDOMAIN：这个名字不存在。",
      nodata: "这个名字没有 {type} 记录。",
      error: "连不上 Cloudflare DNS，可以改用 dig +short {name} 查询。",
      ttl: "TTL {ttl} 秒",
    },
  };

  // Translations of the static page. English lives in the HTML itself.
  const ZH = {
    skip: "跳到正文",
    "nav.names": "命名规则",
    "nav.certs": "证书",
    "nav.servers": "服务器",
    "nav.faq": "常见问题",
    "hero.t1": "每个\u00a0IP\u00a0地址都有域名，",
    "hero.t2": "还能拿到正规\u00a0SSL\u00a0证书。",
    "hero.lead": "把 IP 地址写进 <code>ipssl.cc</code> 下的域名：它就解析到这个地址，还能申请正规证书，内网地址也行。免费，无需注册。",
    "bar.label": "输入任意 IP 地址或域名",
    "tool.try": "试试",
    "tool.check": "查询",
    "trace.browser": "浏览器",
    "call.cert": "正规 SSL 证书",
    "call.how": "查看命令",
    "ai.label": "或者交给 AI 助手",
    "names.title": "把地址写进域名。",
    "names.lead": "点写成横杠，整个地址就放进了一级标签。地址前面的部分随你起名。无需注册，下面每个名字现在就能用。",
    "anat.label": "你的前缀，可省略",
    "anat.addr": "地址，点写成横杠",
    "anat.zone": "域名后缀",
    "anat.result": "解析结果",
    "forms.name": "域名",
    "forms.result": "解析到",
    "forms.notes": "说明",
    "forms.copy": "复制",
    "rules.title": "规则",
    "rules.r1": "一个名字里有多个地址时，以最右边、最靠近域名后缀的那个为准。",
    "rules.r2": "带前导零的数字（如 <code>010</code>）会被拒绝，免得有人猜它是不是八进制。",
    "rules.r5": "IPv6 也一样：<code>:</code> 写成 <code>-</code>，<code>::</code> 写成 <code>--</code>，地址前面的词单独放一级标签。",
    "rules.r3": "对 IPv4 名字查 AAAA（反过来也一样）会得到空应答，而不是 NXDOMAIN。",
    "rules.r4": "查询 <code>ip.ipssl.cc</code> 的 TXT 记录，返回查询的来源地址，通常是你的解析器。",
    "certs.title": "正规 SSL 证书，公网和内网地址都能申请。",
    "certs.lead": "证书来自 Let's Encrypt 或其他任意 ACME CA，签发给你本人，私钥始终留在你自己的机器上。CA 用什么方式验证，取决于这个地址在哪里。",
    "path.yours": "你的地址",
    "path.public.t": "公网地址",
    "path.public.s": "在服务器上直接申请",
    "path.public.d": "域名解析到你的服务器，CA 会直接连过去验证。在这台服务器上运行一条命令就行。<span class=\"term\">HTTP-01 或 TLS-ALPN-01</span>",
    "path.private.t": "内网地址",
    "path.private.s": "通过 DNS，在任意机器上申请",
    "path.private.d": "CA 访问不到 <code class=\"ip-slot\">192.168.1.10</code>，所以由 ACME 客户端把验证信息提交到 <code>https://ipssl.cc/acme</code>，ipssl.cc 在 DNS 里替你应答。<span class=\"term\">DNS-01</span>",
    "certs.f1.t": "任意 CA",
    "certs.f1.d": "这个域没有 CAA 记录，Let's Encrypt、ZeroSSL、Google Trust Services 等都能签发。",
    "certs.f2.t": "能加密，不能证明身份",
    "certs.f2.d": "同一个内网地址存在于无数网络中，任何人都能为同一个名字申请证书。它能加密连接，但不能证明你连上的是谁的机器。",
    "certs.f3.t": "共用一份额度",
    "certs.f3.d": "ipssl.cc 下的所有名字共用 Let's Encrypt 按域名计算的签发额度。证书到期前不必重复申请，或者换一家 CA。",
    "servers.title": "由四台权威服务器应答，分属两家服务商。",
    "servers.lead": "每台都通过 UDP 和 TCP 的 53 端口应答，运行同一份开源服务端。除圣何塞外，其余三台也支持 IPv6。",
    "region.tokyo": "东京",
    "region.la": "洛杉矶",
    "region.hk": "香港",
    "region.sj": "圣何塞",
    "facts.rl.t": "限速，但不会断",
    "facts.rl.d": "UDP 应答按客户端网段限速，服务器不会被拿去攻击别人。收到截断应答的解析器会改用 TCP 重试，TCP 不限速。",
    "facts.log.t": "不记录查询",
    "facts.log.d": "服务器只保留汇总计数，比如回答了多少次 A 查询，不记录查询的名字和客户端地址。",
    "facts.rust.t": "小巧，用 Rust 编写",
    "facts.rust.d": "基于 hickory-dns 的权威服务器。修改配置后热加载，不丢任何一个查询。",
    "faq.title": "常见问题",
    "faq.lead": "没找到答案？到 <a href=\"https://github.com/gonolab/ipssl.cc/issues\">issue 区</a>提问。",
    "faq.q7": "能让 AI 助手帮我配置吗？",
    "faq.a7": "可以。把本页顶部的提示词交给它。<a href=\"/llms.txt\">llms.txt</a> 会告诉它怎么选域名、这个地址适合哪种申请方式，以及具体命令。",
    "faq.q1": "为什么私有地址在我的网络里解析不出来？",
    "faq.a1": "很多路由器（OpenWrt、pfSense、dnsmasq、Fritz!Box 等）开启了 DNS 重绑定保护，会丢弃指向私有地址的应答。在路由器里把 <code>ipssl.cc</code> 加入白名单，或者改用公共解析器。",
    "faq.q2": "能下载 ipssl.cc 的通配符证书吗？",
    "faq.a2": "不能。公开私钥违反 CA 的订户协议，而且任何拿到私钥的人都能吊销证书。请自己申请证书，只需要一条命令。",
    "faq.q3": "为什么 ipssl.cc 不在公共后缀列表（PSL）里？",
    "faq.a3": "PSL 明确不收录把域名里的 IP 解析到该 IP 的服务：同一个 IP 会在不同时间分配给不同的人，不能证明对域名的稳定控制。DNS 解析不依赖 PSL。",
    "faq.q4": "怎么查看我的 DNS 查询是从哪里发出的？",
    "faq.a4": "运行 <code>dig +short TXT ip.ipssl.cc</code>，返回的是查询到达我们时的来源地址，通常是你的递归解析器。",
    "faq.q5": "可以给自己的域名部署一套吗？",
    "faq.a5": "可以。服务端以 MIT 协议开源，用下面的安装脚本就能装到任何 Linux 服务器上。配置和注册商设置见 README。",
    "faq.q6": "怎么举报滥用？",
    "faq.a6": "发邮件到 <a href=\"mailto:abuse@ipssl.cc\">abuse@ipssl.cc</a>，或者在 <a href=\"https://github.com/gonolab/ipssl.cc/issues\">GitHub</a> 上提交 issue，写明域名和它的用途。服务端支持屏蔽列表，用于滥用的名字可以停止解析。",
    "cta.title": "为你自己的域名部署一套。",
    "cta.lead": "安装脚本会下载静态编译的 Linux 程序，对照发布的校验和检查后，配置好 systemd 服务。",
    "cta.github": "在 GitHub 上查看",
    "cta.issue": "提交 issue",
    "footer.llms": "给 AI 助手的 llms.txt",
    "footer.license": "MIT 协议",
    "footer.abuse": "举报滥用",
  };

  // ---------------------------------------------------------------------
  // Page state

  const $ = (sel) => document.querySelector(sel);
  const input = $("#ip-input");
  const bar = $("#bar");
  const display = $("#display");
  const lock = $("#lock");
  const callouts = $("#callouts");
  const nameTitle = $("#name-title");
  const nameTextEl = $("#name-text");
  const certText = $("#cert-text");
  const aiPrompt = $("#ai-prompt");
  const checkBtn = $("#check-btn");
  const barCopy = $("#bar-copy");
  const trace = $("#trace");
  const answer = $("#answer");
  const formsBody = $("#forms-body");

  const i18nNodes = [...document.querySelectorAll("[data-i18n]")];
  const EN = Object.fromEntries(i18nNodes.map((n) => [n.dataset.i18n, n.innerHTML]));

  let lang = "en";
  let current = null; // { ip, kind, names, query } for the address in the bar
  let checkSeq = 0;

  const t = (key, vars = {}) =>
    (STR[lang][key] ?? STR.en[key] ?? key).replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? "");

  const escapeHtml = (s) =>
    String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

  const ICON_COPY = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/></svg>';
  const ICON_CHECK = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5 9.5 17 19 7.5"/></svg>';
  const ICON_X = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M7 7l10 10M17 7 7 17"/></svg>';

  /** Reads the bar: an IP address, or a hostname to run through the parser. */
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
    return ip ? { state: "name", ip, name, labels } : { state: "none", name, labels };
  }

  // ---------------------------------------------------------------------
  // Rendering

  /** The bar's colored copy of what was typed: label, address, rest, zone. */
  function renderDisplay(r) {
    const raw = input.value.trim();
    let parts;
    if (r.state === "ip") {
      parts = [["a", raw]];
    } else if (r.state === "name" || r.state === "none") {
      const body = r.labels.join(".");
      const zone = body ? `.${ZONE}` : ZONE;
      const span = r.state === "name" ? addressSpan(r.labels) : null;
      parts = span
        ? [["p", body.slice(0, span[0])], ["a", body.slice(span[0], span[1])], ["p", body.slice(span[1])], ["z", zone]]
        : [["p", body], ["z", zone]];
    } else {
      parts = [["p", raw]];
    }
    display.innerHTML = parts
      .filter(([, text]) => text)
      .map(([cls, text]) => `<span class="${cls}">${escapeHtml(text)}</span>`)
      .join("");
  }

  const badge = (ip) => `<strong>IPv${ip.v}</strong>`;

  /** The two annotations under the bar and the prompt for an AI agent. */
  function renderCallouts(r) {
    let title;
    let text;
    let cert;
    if (r.state === "ip" || r.state === "name") {
      const ip = ipText(r.ip);
      const kind = kindOf(r.ip);
      if (r.state === "ip") {
        title = escapeHtml(t("name.pending"));
        text = badge(r.ip) + escapeHtml(t("found", { name: nameText(namesFor(r.ip)[0]), ip }));
      } else {
        title = escapeHtml(t("name.resolves", { ip }));
        text = badge(r.ip) + escapeHtml(t(`kind.${kind}`));
      }
      cert = t(`cert.${kind}`, { ip });
    } else if (r.state === "none") {
      title = escapeHtml(t("name.noneTitle"));
      text = escapeHtml(t("name.none"));
      cert = t("cert.none");
    } else if (r.state === "error") {
      title = escapeHtml(t("name.errorTitle"));
      text = escapeHtml(t(r.msg));
      cert = t("cert.none");
    } else {
      title = escapeHtml(t("name.emptyTitle"));
      text = escapeHtml(t("empty"));
      cert = t("cert.none");
    }
    nameTitle.innerHTML = title;
    nameTextEl.innerHTML = text;
    certText.textContent = cert;
    callouts.dataset.state = r.state;
    aiPrompt.textContent = r.ip ? t("ai.prompt", { ip: ipText(r.ip) }) : t("ai.promptNoIp");
  }

  /** The forms table: every way to write the address, each one copyable. */
  function renderForms(ip) {
    const z = `.${ZONE}`;
    let rows;
    if (ip.v === 4) {
      const dashed = ip.a.join("-");
      const dotted = ip.a.join(".");
      const hex = ip.a.map((o) => o.toString(16).padStart(2, "0")).join("");
      rows = [
        ["", dashed, "", "form.rec"],
        ["app-", dashed, "", "form.words"],
        ["", dashed, "-app", ""],
        ["app.", dashed, "", "form.sub"],
        ["", dotted, "", "form.dotted"],
        ["app.", dotted, "", ""],
        ["", hex, "", "form.hex"],
      ];
    } else {
      const label = v6Label(ip.a);
      const full = ip.a.map((g) => g.toString(16)).join("-");
      rows = [
        ["", label, "", "form.v6"],
        ["app.", label, "", "form.v6words"],
      ];
      if (full !== label) rows.push(["", full, "", "form.v6full"]);
    }
    const resolved = escapeHtml(ipText(ip));
    formsBody.innerHTML = rows
      .map(([pre, addr, post, note]) => {
        const name = pre + addr + post + z;
        // Notes come from the string tables above, never from the input.
        const noteHtml = note ? STR[lang][note] ?? STR.en[note] : "";
        return `<tr><td class="n"><code>${escapeHtml(pre)}<span class="a">${escapeHtml(addr)}</span>${escapeHtml(post)}<span class="z">${z}</span></code></td><td class="r"><code>${resolved}</code></td><td class="note">${noteHtml}</td><td class="c"><button class="copy" type="button" data-copy="${escapeHtml(name)}" aria-label="${escapeHtml(t("copyName", { name }))}">${ICON_COPY}</button></td></tr>`;
      })
      .join("");
    $("#forms-caption").textContent = t("forms.caption", { ip: ipText(ip) });
  }

  /** The anatomy figure and both certificate paths follow the bar. */
  function renderElsewhere() {
    const ip = current ? current.ip : { v: 4, a: [192, 168, 1, 10] };
    const kind = current ? current.kind : "private";
    const rec = namesFor(ip)[0];
    $("#anat-label").textContent = ip.v === 4 ? "app-" : "app.";
    $("#anat-addr").textContent = rec.addr;
    $("#anat-ip").textContent = ipText(ip);
    renderForms(ip);

    const name = current ? current.query : nameText(rec);
    const publicHere = current && (kind === "public" || kind === "doc");
    const privateHere = current && kind === "private";
    document.querySelectorAll('.host-slot[data-path="public"]').forEach((el) => {
      el.textContent = publicHere ? name : "203-0-113-10.ipssl.cc";
    });
    document.querySelectorAll('.host-slot[data-path="private"]').forEach((el) => {
      el.textContent = privateHere ? name : "192-168-1-10.ipssl.cc";
    });
    $("#path-public").classList.toggle("is-yours", Boolean(publicHere));
    $("#path-private").classList.toggle("is-yours", Boolean(privateHere));
    $("#note-public").textContent = publicHere
      ? t(kind === "doc" ? "note.doc" : "note.public", { ip: ipText(ip) })
      : t("note.publicEx");
    $("#note-private").textContent = privateHere ? t("note.private") : t("note.privateEx");
    document.querySelectorAll(".ip-slot").forEach((el) => {
      el.textContent = privateHere ? ipText(ip) : "192.168.1.10";
    });
  }

  /** Drops the "https://" only when the name would not fit beside it. */
  function fitScheme() {
    delete bar.dataset.compact;
    if (display.scrollWidth > display.clientWidth + 1) bar.dataset.compact = "";
  }

  // The annotations hang from the lock and the address on thin lines when
  // there is room on both sides; otherwise they stack under the bar.
  const narrow = window.matchMedia("(max-width: 720px)");
  function placeCallouts() {
    fitScheme();
    const box = callouts.getBoundingClientRect();
    const lockBox = lock.getBoundingClientRect();
    const addr = display.querySelector(".a") || display;
    const addrBox = addr.getBoundingClientRect();
    const lockX = lockBox.left + lockBox.width / 2 - box.left;
    const addrX = addrBox.left - box.left + Math.min(addrBox.width / 2, 18);
    const fits = !narrow.matches && lockX >= 210 && box.width - addrX >= 300 && addrX - lockX >= 48;
    callouts.dataset.layout = fits ? "anchored" : "stack";
    if (fits) {
      callouts.style.setProperty("--lock-x", `${Math.round(lockX)}px`);
      callouts.style.setProperty("--addr-x", `${Math.round(addrX)}px`);
    }
  }

  function update() {
    const r = readInput(input.value);
    current = r.ip
      ? { ip: r.ip, kind: kindOf(r.ip), names: namesFor(r.ip), query: r.state === "name" ? r.name : nameText(namesFor(r.ip)[0]) }
      : null;
    input.toggleAttribute("aria-invalid", r.state === "error");
    bar.dataset.kind = current ? current.kind : "none";
    renderDisplay(r);
    renderCallouts(r);
    renderElsewhere();
    checkBtn.disabled = !current;
    barCopy.disabled = !current;
    barCopy.setAttribute("aria-label", current ? t("copyName", { name: current.query }) : t("copy"));
    // A new input makes an earlier check result stale.
    checkSeq++;
    trace.hidden = true;
    trace.dataset.state = "idle";
    answer.textContent = "";
    placeCallouts();
  }

  /** A typed IP address becomes its recommended name, the way a browser completes a URL. */
  function commit() {
    const r = readInput(input.value);
    if (r.state !== "ip") return false;
    input.value = nameText(namesFor(r.ip)[0]);
    update();
    // Replay the settle animation on the new name.
    delete bar.dataset.rewrite;
    void bar.offsetWidth;
    bar.dataset.rewrite = "";
    return true;
  }

  // ---------------------------------------------------------------------
  // Live check over DNS-over-HTTPS (JSON API). Only the name is sent.

  async function check() {
    if (!current) return;
    const seq = ++checkSeq;
    const name = current.query;
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

  barCopy.addEventListener("click", () => {
    if (current) copyText(current.query, barCopy);
  });

  $("#ai-copy").addEventListener("click", (e) => copyText(aiPrompt.textContent, e.currentTarget));

  formsBody.addEventListener("click", (e) => {
    const btn = e.target.closest(".copy");
    if (btn) copyText(btn.dataset.copy, btn);
  });

  document.querySelectorAll("[data-copy-snip]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const lines = btn.closest(".code-panel").querySelectorAll(".snip:not([hidden]) .ln");
      // One line per block; leave out the prompts and the comment lines.
      const text = [...lines]
        .map((ln) =>
          [...ln.childNodes]
            .filter((n) => !(n.nodeType === 1 && n.matches(".prompt, .comment")))
            .map((n) => n.textContent)
            .join(""),
        )
        .filter((line) => line.trim())
        .join("\n");
      copyText(text, btn);
    });
  });

  $("#install-copy").addEventListener("click", (e) => {
    copyText($("#install-cmd").textContent, e.currentTarget);
  });

  // Commands may wrap on narrow screens, but only between arguments: each
  // space-separated word goes in a span that never breaks inside, since a
  // flag or URL split at a hyphen reads as two arguments.
  document.querySelectorAll(".snip .ln").forEach((ln) => {
    [...ln.childNodes].forEach((node) => {
      if (node.nodeType !== Node.TEXT_NODE || !node.textContent.trim()) return;
      const frag = document.createDocumentFragment();
      node.textContent.split(/( +)/).forEach((part) => {
        if (!part) return;
        if (part.startsWith(" ")) {
          frag.append(part);
        } else {
          const word = document.createElement("span");
          word.className = "w";
          word.textContent = part;
          frag.append(word);
        }
      });
      node.replaceWith(frag);
    });
  });

  // ---------------------------------------------------------------------
  // Tabs, one group per code panel, with arrow-key navigation.

  document.querySelectorAll('[role="tablist"]').forEach((list) => {
    const tabs = [...list.querySelectorAll('[role="tab"]')];
    const select = (tab, focus) => {
      tabs.forEach((other) => {
        const on = other === tab;
        other.setAttribute("aria-selected", String(on));
        other.tabIndex = on ? 0 : -1;
        document.getElementById(other.getAttribute("aria-controls")).hidden = !on;
      });
      if (focus) tab.focus();
    };
    tabs.forEach((tab, i) => {
      tab.addEventListener("click", () => select(tab, false));
      tab.addEventListener("keydown", (e) => {
        const step = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
        if (step) {
          e.preventDefault();
          select(tabs[(i + step + tabs.length) % tabs.length], true);
        } else if (e.key === "Home" || e.key === "End") {
          e.preventDefault();
          select(tabs[e.key === "Home" ? 0 : tabs.length - 1], true);
        }
      });
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
    document.querySelectorAll("[data-copy-snip]").forEach((b) => b.setAttribute("aria-label", t("copyCmd")));
    $("#ai-copy").setAttribute("aria-label", t("copyPrompt"));
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
  input.addEventListener("blur", commit);
  input.addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    e.preventDefault();
    commit();
    check();
  });
  checkBtn.addEventListener("click", () => {
    commit();
    check();
  });
  // Clicking anywhere in the address edits it, as in a browser.
  $("#url").addEventListener("click", (e) => {
    if (e.target !== input) input.focus();
  });
  document.querySelectorAll("[data-example]").forEach((btn) => {
    btn.addEventListener("click", () => {
      input.value = btn.dataset.example;
      commit();
    });
  });

  new ResizeObserver(placeCallouts).observe(bar);
  narrow.addEventListener("change", placeCallouts);
  document.fonts?.ready.then(placeCallouts);

  let saved = null;
  try {
    saved = localStorage.getItem("lang");
  } catch {
    /* ignore */
  }
  setLang(saved === "zh" ? "zh" : "en", false);
})();
