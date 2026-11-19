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

  /** Eight dash-separated decimal octets: two IPv4 addresses (10-0-0-1-192-168-1-1). */
  const twoV4 = (t) => t.length === 8 && allOctets(t) !== null;

  /**
   * A whole label as IPv6, dashes for colons. Eight decimal octets also make
   * a full IPv6 address (10:0:0:1:192:168:1:1), but the server reads them as
   * two IPv4 addresses, and the rightmost one wins, so they are not IPv6.
   */
  const dashedV6 = (label) =>
    label.includes("-") && !twoV4(label.split("-")) ? parseV6(label.replace(/-/g, ":"), false) : null;

  /** An address inside one label: dashed IPv6, dashed IPv4 or eight hex digits. */
  function singleLabel(label) {
    const v6 = dashedV6(label);
    if (v6) return { v: 6, a: v6 };
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

  /** Address text; an IPv4-mapped address keeps its IPv4 tail (::ffff:10.0.0.1). */
  const ipText = (ip) => {
    if (ip.v === 4) return ip.a.join(".");
    const v4 = mappedV4(ip);
    return v4 ? `::ffff:${v4.a.join(".")}` : v6Text(ip.a);
  };

  /**
   * A dashed IPv6 label the server reads back as the same address, and that
   * a CA accepts. Eight groups that all look like decimal octets
   * (1-2-3-4-5-6-7-8) would be two IPv4 addresses, and a label with "--" as
   * its third and fourth characters (fd--1) is refused by Let's Encrypt, so
   * either one gets its first group written with four digits (0001-2-3-4-5-6-7-8).
   */
  function keepV6(label) {
    const t = label.split("-");
    if (!twoV4(t) && label.slice(2, 4) !== "--") return label;
    return t[0].padStart(4, "0") + label.slice(t[0].length);
  }

  /**
   * IPv6 as one label. A label may not start or end with "-", so a leading
   * or trailing "::" gets an explicit zero group (::1 becomes 0--1).
   */
  function v6Label(a) {
    let t = v6Text(a);
    if (t.startsWith("::")) t = `0${t}`;
    if (t.endsWith("::")) t += "0";
    return keepV6(t.replace(/:/g, "-"));
  }

  /** IPv6 as one label with every group written out (2001-db8-0-0-0-0-0-1). */
  const v6Full = (a) => keepV6(a.map((g) => g.toString(16)).join("-"));

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
    const full = v6Full(ip.a);
    const names = [
      { pre: "", addr: label, tag: "rec" },
      { pre: "app.", addr: label, tag: "sub" },
    ];
    if (full !== label) names.push({ pre: "", addr: full, tag: "expanded" });
    return names.map((n) => ({ ...n, zone: z }));
  }

  const nameText = (n) => n.pre + n.addr + n.zone;

  /** The IPv4 address inside ::ffff:0:0/96 (::ffff:192.168.1.10), or null. */
  const mappedV4 = (ip) =>
    ip.v === 6 && ip.a.slice(0, 5).every((g) => g === 0) && ip.a[5] === 0xffff
      ? { v: 4, a: [ip.a[6] >> 8, ip.a[6] & 0xff, ip.a[7] >> 8, ip.a[7] & 0xff] }
      : null;

  /** fe80::/10, which needs an interface scope that a name cannot carry. */
  const isLinkLocal6 = (ip) => ip.v === 6 && (ip.a[0] & 0xffc0) === 0xfe80;

  /** Where an address can be used: public, private, documentation, other. */
  function kindOf(ip) {
    // An IPv4-mapped address counts as the IPv4 address inside, as on the server.
    const v4 = mappedV4(ip);
    if (v4) return kindOf(v4);
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
    if (dashedV6(label)) return [0, label.length];
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
      outside: "The final dot ends the name there, and it is not under ipssl.cc. Drop the dot to put it in front of .ipssl.cc.",
      hyphen: "A label, the part between two dots, cannot start or end with a dash.",
      labelLong: "A label, the part between two dots, can be at most 63 characters long.",
      nameLong: "With .ipssl.cc, the whole name can be at most 253 characters long.",
      found: "{name} resolves to {ip}.",
      "name.resolves": "Resolves to {ip}",
      "name.pending": "Press Enter to turn it into a name",
      "name.noneTitle": "No IP address in this name",
      "name.none": "Put one in, as in app.10-0-2-2.ipssl.cc, and the name resolves to that address.",
      "name.errorTitle": "Not an IP address or a hostname",
      "name.badTitle": "Not a valid hostname",
      "name.outsideTitle": "Not a name under ipssl.cc",
      "name.emptyTitle": "Type an IP address",
      "kind.public": "Public address. No DNS server of your own, nothing to register.",
      "kind.private": "Private address. Nothing to set up, though some routers block answers like this one.",
      "kind.linklocal": "Link-local address. Most systems and browsers cannot reach it by name, since a name carries no interface scope. Use a ULA (fd00::/8) or a global address.",
      "kind.doc": "Documentation address, reserved for examples.",
      "kind.other": "Not a public unicast address.",
      "cert.public": "Run one command on the server at {ip}, and Let's Encrypt or any other CA issues it.",
      "cert.doc": "{ip} is an example address, reserved for documentation, so no CA validates it. Type your server's public address instead.",
      "cert.private": "A CA cannot reach {ip}, so ipssl.cc proves the name through DNS for you. Get it from any machine.",
      "cert.tooLong": "This name is too long for a DNS-01 challenge: with _acme-challenge. in front, it passes 253 characters. Keep it to 237.",
      "cert.other": "No CA issues certificates for {ip}.",
      "cert.none": "Put an IP address in the name to get a certificate for it.",
      "le.labels": "Let's Encrypt refuses names with more than 10 labels, and this one has {n}.",
      "le.rldh": "Let's Encrypt refuses labels with -- as the third and fourth characters, such as {label}.",
      "ai.prompt": "Read https://ipssl.cc/llms.txt, then give my machine at {ip} a hostname under ipssl.cc and an SSL certificate for it.",
      "ai.promptName": "Read https://ipssl.cc/llms.txt, then give my machine at {ip} the hostname {name} and an SSL certificate for it.",
      "ai.promptNoIp": "Read https://ipssl.cc/llms.txt, then give my machine a hostname under ipssl.cc and an SSL certificate for it.",
      "forms.caption": "Every way to write {ip}",
      "anat.label": "Your label, optional",
      "anat.addr4": "The address, dots written as dashes",
      "anat.addr6": "The address, <code>:</code> written as <code>-</code> and <span class=\"nobr\"><code>::</code> as <code>--</code></span>",
      "family.bar": "Your address from the bar above",
      "family.example4": "An example. Type an IPv4 address above to see yours.",
      "family.example6": "An example. Type an IPv6 address above to see yours.",
      "form.rec": "<strong>Recommended.</strong> One label, easiest to get certificates for",
      "form.words": "Words before or after the address, joined with <code>-</code>",
      "form.sub": "Any number of subdomain levels",
      "form.dotted": "Dotted form",
      "form.hex": "Eight hex digits",
      "form.v6words": "Words in front of an IPv6 address go in their own label",
      "form.v6full": "Every group written out",
      "note.public": "Run it on the server at {ip}.",
      "note.doc": "Example only: no CA validates {ip}. Type your server's public IP above.",
      "note.publicEx": "Example name. Type a public IP above to use yours.",
      "note.private": "Run it on any machine with internet access.",
      "note.privateEx": "Example name. Type a private IP above to use yours.",
      "note.tooLong": "Example name. Yours is too long for a DNS-01 challenge; keep it to 237 characters.",
      copy: "Copy",
      copied: "Copied",
      copyFailed: "Could not copy. Select the text and copy it yourself.",
      copyName: "Copy {name}",
      copyPrompt: "Copy prompt",
      copyCmd: "Copy command",
      copyInstall: "Copy install command",
      modes: "What is on port 80",
      checking: "Asking Cloudflare DNS…",
      match: "Resolves correctly",
      mismatch: "Expected {want}",
      mismatchOnly: "Expected only {want}",
      nx: "NXDOMAIN: the name does not exist.",
      nodata: "No {type} record for this name.",
      rcode: "DNS error {rcode}: Cloudflare DNS got no answer for this name.",
      error: "Could not reach Cloudflare DNS. Try dig +short {type} {name} instead.",
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
      outside: "末尾的点表示名字到此结束，而它不在 ipssl.cc 下。去掉这个点，它就会接在 .ipssl.cc 前面。",
      hyphen: "标签（两个点之间的部分）不能以横杠开头或结尾。",
      labelLong: "标签（两个点之间的部分）最长 63 个字符。",
      nameLong: "加上 .ipssl.cc，整个名字最长 253 个字符。",
      found: "{name} 解析到 {ip}。",
      "name.resolves": "解析到 {ip}",
      "name.pending": "按回车把它变成域名",
      "name.noneTitle": "这个名字里没有 IP 地址",
      "name.none": "放一个进去，比如 app.10-0-2-2.ipssl.cc，名字就会解析到这个地址。",
      "name.errorTitle": "这不是 IP 地址，也不是域名",
      "name.badTitle": "这不是有效的域名",
      "name.outsideTitle": "这不是 ipssl.cc 下的名字",
      "name.emptyTitle": "输入一个 IP 地址",
      "kind.public": "公网地址。不用自己搭 DNS，也不用注册。",
      "kind.private": "私有地址。不用任何设置，但有些路由器会拦截这类应答。",
      "kind.linklocal": "链路本地地址。域名带不了网卡标识，多数系统和浏览器无法通过域名访问它。请改用 ULA（fd00::/8）或全局地址。",
      "kind.doc": "文档示例地址，只用于举例。",
      "kind.other": "不是公网单播地址。",
      "cert.public": "在 {ip} 这台服务器上运行一条命令，Let's Encrypt 等任意 CA 都能签发。",
      "cert.doc": "{ip} 是文档专用的示例地址，没有 CA 会验证它。请换成你服务器的公网地址。",
      "cert.private": "CA 访问不到 {ip}，由 ipssl.cc 通过 DNS 替你完成验证，在任意机器上都能申请。",
      "cert.tooLong": "这个名字太长，做不了 DNS-01 验证：前面加上 _acme-challenge. 后超过 253 个字符。请控制在 237 个字符以内。",
      "cert.other": "{ip} 这类地址申请不到证书。",
      "cert.none": "名字里要有 IP 地址，才能为它申请证书。",
      "le.labels": "Let's Encrypt 不接受超过 10 级标签的名字，这个名字有 {n} 级。",
      "le.rldh": "Let's Encrypt 不接受第 3、4 个字符是 -- 的标签，比如 {label}。",
      "ai.prompt": "请阅读 https://ipssl.cc/llms.txt，然后给 IP 为 {ip} 的机器配一个 ipssl.cc 域名，并为它申请 SSL 证书。",
      "ai.promptName": "请阅读 https://ipssl.cc/llms.txt，然后给 IP 为 {ip} 的机器配上域名 {name}，并为它申请 SSL 证书。",
      "ai.promptNoIp": "请阅读 https://ipssl.cc/llms.txt，然后给我的机器配一个 ipssl.cc 域名，并为它申请 SSL 证书。",
      "forms.caption": "{ip} 的所有写法",
      "anat.label": "可选前缀",
      "anat.addr4": "地址，点写成横杠",
      "anat.addr6": "地址，<code>:</code> 写成 <code>-</code>，<span class=\"nobr\"><code>::</code> 写成 <code>--</code></span>",
      "family.bar": "来自上面地址栏的地址",
      "family.example4": "这是示例。在上面输入 IPv4 地址，就会换成你的。",
      "family.example6": "这是示例。在上面输入 IPv6 地址，就会换成你的。",
      "form.rec": "<strong>推荐。</strong>只有一级标签，最容易申请证书",
      "form.words": "地址前后可以加词，用 <code>-</code> 连接",
      "form.sub": "子域名层级不限",
      "form.dotted": "点分写法",
      "form.hex": "八位十六进制",
      "form.v6words": "IPv6 地址前面的词要单独放一级标签",
      "form.v6full": "每一组都完整写出",
      "note.public": "在 {ip} 这台服务器上运行。",
      "note.doc": "仅作示例：没有 CA 会验证 {ip}。请在上面输入你服务器的公网 IP。",
      "note.publicEx": "示例域名。在上面输入公网 IP，就会换成你的。",
      "note.private": "在任意一台能上网的机器上运行。",
      "note.privateEx": "示例域名。在上面输入内网 IP，就会换成你的。",
      "note.tooLong": "示例域名。你的名字太长，做不了 DNS-01 验证，请控制在 237 个字符以内。",
      copy: "复制",
      copied: "已复制",
      copyFailed: "复制失败，请手动选中文字复制。",
      copyName: "复制 {name}",
      copyPrompt: "复制提示词",
      copyCmd: "复制命令",
      copyInstall: "复制安装命令",
      modes: "80 端口的情况",
      checking: "正在查询 Cloudflare DNS…",
      match: "解析正确",
      mismatch: "预期是 {want}",
      mismatchOnly: "预期只有 {want}",
      nx: "NXDOMAIN：这个名字不存在。",
      nodata: "这个名字没有 {type} 记录。",
      rcode: "DNS 错误 {rcode}：Cloudflare DNS 没拿到这个名字的应答。",
      error: "连不上 Cloudflare DNS，可以改用 dig +short {type} {name} 查询。",
      ttl: "TTL {ttl} 秒",
    },
  };

  // Translations of the static page. English lives in the HTML itself.
  const ZH = {
    skip: "跳到正文",
    "nav.names": "命名规则",
    "nav.certs": "证书",
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
    "names.lead": "把地址里的符号写成横杠，整个地址就放进了一级标签：IPv4 的点、IPv6 的冒号都一样。地址前面的部分随你起名。无需注册，下面每个名字现在就能用。",
    "anat.zone": "域名后缀",
    "anat.result": "解析结果",
    "forms.name": "域名",
    "forms.result": "解析到",
    "forms.notes": "说明",
    "forms.copy": "复制",
    "rules.title": "规则",
    "rules.r1": "一个名字里有多个地址时，以最右边、最靠近域名后缀的那个为准。",
    "rules.r2": "带前导零的数字（如 <code>010</code>）会被拒绝，免得有人猜它是不是八进制。",
    "rules.r3": "对 IPv4 名字查 AAAA（反过来也一样）会得到空应答，而不是 NXDOMAIN。",
    "rules.r4": "查询 <code>ip.ipssl.cc</code> 的 TXT 记录，返回查询的来源地址，通常是你的解析器。",
    "certs.title": "正规 SSL 证书，公网和内网地址都能申请。",
    "certs.lead": "证书来自 Let's Encrypt 或其他任意 ACME CA，签发给你本人，私钥始终留在你自己的机器上。CA 用什么方式验证，取决于这个地址在哪里。",
    "path.yours": "你的地址",
    "path.public.t": "公网地址",
    "path.public.s": "在服务器上直接申请",
    "path.public.d": "域名解析到你的服务器，CA 会直接连过去验证。在这台服务器上运行下面的命令就行。<span class=\"term\">HTTP-01 或 TLS-ALPN-01</span>",
    "path.private.t": "内网地址",
    "path.private.s": "通过 DNS，在任意机器上申请",
    "mode.label": "80 端口",
    "mode.free": "空闲",
    "mode.nginx": "nginx 在用",
    "path.private.d": "CA 访问不到 <code class=\"ip-slot\">192.168.1.10</code>，所以由 ACME 客户端把验证信息提交到 <code>https://ipssl.cc/acme</code>，ipssl.cc 在 DNS 里替你应答。<span class=\"term\">DNS-01</span>",
    "certs.f1.t": "任意 CA",
    "certs.f1.d": "这个域没有 CAA 记录，Let's Encrypt、ZeroSSL、Google Trust Services 等都能签发。",
    "certs.f2.t": "能加密，不能证明身份",
    "certs.f2.d": "同一个内网地址存在于无数网络中，任何人都能为同一个名字申请证书。它能加密连接，但不能证明你连上的是谁的机器。",
    "certs.f3.t": "共用一份额度",
    "certs.f3.d": "ipssl.cc 下的所有名字共用 Let's Encrypt 按域名计算的签发额度；完全相同的一组名字每 7 天只能签 5 张，所有人共用。常见的名字请加上自己的标签，比如 <code>myname-192-168-1-10.ipssl.cc</code>。",
    "certs.f4.t": "别人也能吊销",
    "certs.f4.d": "能验证某个名字的人，也能吊销它的证书。公网 IP 换了主人以后，前一任在一段时间内可能仍持有、甚至还能申请这个名字的证书。",
    "certs.f5.t": "写进公开日志",
    "certs.f5.d": "签发的每张证书都会写进公开的证书透明度（CT）日志，证书里的名字连同标签和地址，任何人都能搜到。",
    "certs.f6.t": "Cookie 和存储",
    "certs.f6.d": "不要用 <code>Domain=ipssl.cc</code> 设置 Cookie：别人的名字也能设置这种 Cookie。请用仅限当前主机（host-only）或带 <code>__Host-</code> 前缀的 Cookie。同一个名字在两个网络里仍是浏览器里的同一个源，本地存储、Service Worker 和保存的密码都会沿用。",
    "faq.title": "常见问题",
    "faq.lead": "没找到答案？到 <a href=\"https://github.com/gonolab/ipssl.cc/issues\">issue 区</a>提问。",
    "faq.q7": "能让 AI 助手帮我配置吗？",
    "faq.a7": "可以。把本页顶部的提示词交给它。<a href=\"/llms.txt\">llms.txt</a> 会告诉它怎么选域名、这个地址适合哪种申请方式，以及具体命令。",
    "faq.q1": "为什么私有地址在我的网络里解析不出来？",
    "faq.a1": "很多路由器（OpenWrt、pfSense、dnsmasq、Fritz!Box 等）开启了 DNS 重绑定保护，会丢弃指向私有地址的应答。只把用到的名字加入白名单，比如 dnsmasq 里的 <code>rebind-domain-ok=/192-168-1-10.ipssl.cc/</code>，或者放行整个 <code>ipssl.cc</code>，也可以改用公共解析器。",
    "faq.q2": "能下载 ipssl.cc 的通配符证书吗？",
    "faq.a2": "不能。公开私钥违反 CA 的订户协议，而且任何拿到私钥的人都能吊销证书。请自己申请证书，只需要一条命令。",
    "faq.q3": "为什么 ipssl.cc 不在公共后缀列表（PSL）里？",
    "faq.a3": "PSL 明确不收录把域名里的 IP 解析到该 IP 的服务：同一个 IP 会在不同时间分配给不同的人，不能证明对域名的稳定控制。DNS 解析不依赖 PSL，浏览器却依赖：这里的任何名字都能为整个 <code>ipssl.cc</code> 设置 Cookie，所以你的 Cookie 要限定在当前主机。",
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

  // Shown in the names section when the bar holds the other family.
  const EXAMPLE = {
    4: { v: 4, a: [192, 168, 1, 10] },
    6: { v: 6, a: [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1] },
  };
  const familyTabs = [...document.querySelectorAll(".family [role=tab]")];

  let lang = "en";
  let family = 4; // address family shown in the names section
  let reading = { state: "empty" }; // what readInput made of the bar
  let current = null; // { ip, kind, query } for the address in the bar
  let target = null; // { name, ip } for the live check; ip is null for a name without one
  let result = null; // the live check, kept as data so a language switch can redraw it
  let checkSeq = 0;

  const t = (key, vars = {}) =>
    (STR[lang][key] ?? STR.en[key] ?? key).replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? "");

  const escapeHtml = (s) =>
    String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

  const ICON_COPY = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/></svg>';
  const ICON_CHECK = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5 9.5 17 19 7.5"/></svg>';
  const ICON_X = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M7 7l10 10M17 7 7 17"/></svg>';

  const MAX_NAME = 253; // DNS limit for a whole name, without the final dot
  const MAX_LABEL = 63;
  // A DNS-01 challenge lives at _acme-challenge.<name>, which must fit too.
  const MAX_DNS01_NAME = MAX_NAME - "_acme-challenge.".length;

  /** Reads the bar: an IP address, or a hostname to run through the parser. */
  function readInput(raw) {
    let s = raw.trim().toLowerCase().replace(/^\[|\]$/g, "");
    // A final dot makes the name absolute: it must already end in the zone.
    const absolute = s.endsWith(".");
    if (absolute) s = s.slice(0, -1);
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
    const inZone = s === ZONE || s.endsWith(`.${ZONE}`);
    if (absolute && !inZone) return { state: "error", msg: "outside", title: "name.outsideTitle" };
    const name = inZone ? s : `${s}.${ZONE}`;
    const labels = s === ZONE ? [] : inZone ? s.slice(0, -ZONE.length - 1).split(".") : s.split(".");
    // Hostname rules: letters, digits and inner dashes, 63 per label, 253 in all.
    if (labels.some((l) => l.startsWith("-") || l.endsWith("-"))) return { state: "error", msg: "hyphen", title: "name.badTitle" };
    if (labels.some((l) => l.length > MAX_LABEL)) return { state: "error", msg: "labelLong", title: "name.badTitle" };
    if (name.length > MAX_NAME) return { state: "error", msg: "nameLong", title: "name.badTitle" };
    const ip = extractIp(labels);
    return ip ? { state: "name", ip, name, labels } : { state: "none", name, labels };
  }

  /** Why Let's Encrypt would refuse `name` though DNS answers for it. */
  function leProblems(name) {
    const labels = name.split(".");
    const out = [];
    if (labels.length > 10) out.push(t("le.labels", { n: labels.length }));
    // "ab--" is reserved for encodings; only punycode's "xn--" is allowed.
    const reserved = labels.find((l) => l.length >= 4 && l.slice(2, 4) === "--" && !l.startsWith("xn--"));
    if (reserved) out.push(t("le.rldh", { label: reserved }));
    return out;
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

  const warn = (s) => `<span class="callout-warn">${escapeHtml(s)}</span>`;

  /** The two annotations under the bar and the prompt for an AI agent. */
  function renderCallouts(r) {
    let title;
    let text;
    let cert;
    if (r.state === "ip" || r.state === "name") {
      const ip = ipText(r.ip);
      const { kind, query } = current;
      if (r.state === "ip") {
        title = escapeHtml(t("name.pending"));
        text = badge(r.ip) + escapeHtml(t("found", { name: query, ip }));
      } else {
        title = escapeHtml(t("name.resolves", { ip }));
        text = badge(r.ip) + escapeHtml(t(isLinkLocal6(r.ip) ? "kind.linklocal" : `kind.${kind}`));
      }
      if (kind === "private" && query.length > MAX_DNS01_NAME) {
        cert = warn(t("cert.tooLong"));
      } else {
        cert = escapeHtml(t(`cert.${kind}`, { ip }));
        if (kind === "public" || kind === "private") cert += leProblems(query).map(warn).join("");
      }
    } else if (r.state === "none") {
      title = escapeHtml(t("name.noneTitle"));
      text = escapeHtml(t("name.none"));
      cert = escapeHtml(t("cert.none"));
    } else if (r.state === "error") {
      title = escapeHtml(t(r.title || "name.errorTitle"));
      text = escapeHtml(t(r.msg));
      cert = escapeHtml(t("cert.none"));
    } else {
      title = escapeHtml(t("name.emptyTitle"));
      text = escapeHtml(t("empty"));
      cert = escapeHtml(t("cert.none"));
    }
    nameTitle.innerHTML = title;
    nameTextEl.innerHTML = text;
    certText.innerHTML = cert;
    callouts.dataset.state = r.state;
    // A typed name goes into the prompt whole, so the agent keeps its labels.
    aiPrompt.textContent =
      r.state === "name"
        ? t("ai.promptName", { ip: ipText(r.ip), name: r.name })
        : r.ip
          ? t("ai.prompt", { ip: ipText(r.ip) })
          : t("ai.promptNoIp");
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
      const full = v6Full(ip.a);
      rows = [
        ["", label, "", "form.rec"],
        ["app.", label, "", "form.v6words"],
      ];
      if (full !== label) rows.push(["", full, "", "form.v6full"]);
    }
    // Long names wrap where a reader expects it: after "-" and ":", before
    // "." and before the zone, which stays whole. The copy button stays in view.
    const wrap = (s) => escapeHtml(s).replace(/([-:]+)/g, "$1<wbr>").replace(/\./g, "<wbr>.");
    // An IPv4 answer is short enough to keep whole; IPv6 may break after ":".
    const resolved = ip.v === 6 ? wrap(ipText(ip)) : escapeHtml(ipText(ip));
    formsBody.innerHTML = rows
      .map(([pre, addr, post, note]) => {
        const name = pre + addr + post + z;
        // Notes come from the string tables above, never from the input.
        const noteHtml = note ? STR[lang][note] ?? STR.en[note] : "";
        return `<tr><td class="n"><code>${wrap(pre)}<span class="a">${wrap(addr)}</span>${wrap(post)}<wbr><span class="z">${z}</span></code></td><td class="r"><code>${resolved}</code></td><td class="note">${noteHtml}</td><td class="c"><button class="copy" type="button" data-copy="${escapeHtml(name)}" aria-label="${escapeHtml(t("copyName", { name }))}">${ICON_COPY}</button></td></tr>`;
      })
      .join("");
    $("#forms-caption").textContent = t("forms.caption", { ip: ipText(ip) });
  }

  /** The anatomy figure and both certificate paths follow the bar. */
  function renderElsewhere() {
    renderNames();
    const ip = current ? current.ip : EXAMPLE[4];
    const kind = current ? current.kind : "private";
    const rec = namesFor(ip)[0];

    const name = current ? current.query : nameText(rec);
    const publicHere = Boolean(current) && kind === "public";
    // A documentation address may fill the example, but it is nobody's address.
    const docHere = Boolean(current) && kind === "doc";
    const tooLong = Boolean(current) && kind === "private" && name.length > MAX_DNS01_NAME;
    const privateHere = Boolean(current) && kind === "private" && !tooLong;
    document.querySelectorAll('.host-slot[data-path="public"]').forEach((el) => {
      el.textContent = publicHere || docHere ? name : "203-0-113-10.ipssl.cc";
    });
    document.querySelectorAll('.host-slot[data-path="private"]').forEach((el) => {
      el.textContent = privateHere ? name : "192-168-1-10.ipssl.cc";
    });
    $("#path-public").classList.toggle("is-yours", publicHere);
    $("#path-private").classList.toggle("is-yours", privateHere);
    const notePublic = $("#note-public");
    notePublic.textContent = publicHere
      ? t("note.public", { ip: ipText(ip) })
      : docHere
        ? t("note.doc", { ip: ipText(ip) })
        : t("note.publicEx");
    notePublic.dataset.tone = docHere ? "warn" : "";
    const notePrivate = $("#note-private");
    notePrivate.textContent = privateHere ? t("note.private") : tooLong ? t("note.tooLong") : t("note.privateEx");
    notePrivate.dataset.tone = tooLong ? "warn" : "";
    document.querySelectorAll(".ip-slot").forEach((el) => {
      el.textContent = privateHere ? ipText(ip) : "192.168.1.10";
    });
  }

  /** Drops the "https://" only when the name would not fit beside it. */
  function fitScheme() {
    delete bar.dataset.compact;
    if (display.scrollWidth > display.clientWidth + 1) bar.dataset.compact = "";
  }

  /**
   * The names section: the bar's address when it is of the family picked in
   * the switch, otherwise an example of that family.
   */
  function renderNames() {
    const fromBar = Boolean(current) && current.ip.v === family;
    const ip = fromBar ? current.ip : EXAMPLE[family];
    $("#anat-label").textContent = ip.v === 4 ? "app-" : "app.";
    $("#anat-addr").textContent = namesFor(ip)[0].addr;
    $("#anat-ip").textContent = ipText(ip);
    $("#anat-label-cap").textContent = t("anat.label");
    // Captions come from the string tables above, never from the input.
    $("#anat-addr-cap").innerHTML = t(`anat.addr${ip.v}`);
    renderForms(ip);
    $("#family-note").textContent = fromBar ? t("family.bar") : t(`family.example${family}`);
    familyTabs.forEach((tab) => {
      const on = Number(tab.dataset.family) === family;
      tab.setAttribute("aria-selected", String(on));
      tab.tabIndex = on ? 0 : -1;
    });
    $("#names-panel").setAttribute("aria-labelledby", `fam-${family}`);
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

  /** The bar changed: read it again, drop the earlier check, redraw. */
  function update() {
    const r = readInput(input.value);
    reading = r;
    current = r.ip ? { ip: r.ip, kind: kindOf(r.ip), query: r.state === "name" ? r.name : nameText(namesFor(r.ip)[0]) } : null;
    // A name without an address can still be looked up; it just has no expected answer.
    target = current ? { name: current.query, ip: current.ip } : r.state === "none" ? { name: r.name, ip: null } : null;
    if (current) family = current.ip.v;
    // A new input makes an earlier check stale, and one still running is dropped.
    checkSeq++;
    result = null;
    render();
  }

  /** Draws the page from the state above, in the current language. */
  function render() {
    const r = reading;
    input.setAttribute("aria-invalid", r.state === "error" ? "true" : "false");
    bar.dataset.kind = current ? current.kind : "none";
    renderDisplay(r);
    renderCallouts(r);
    renderElsewhere();
    checkBtn.disabled = !target || result?.phase === "run";
    barCopy.disabled = !target;
    barCopy.setAttribute("aria-label", target ? t("copyName", { name: target.name }) : t("copy"));
    renderAnswer();
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

  const RCODES = { 1: "FORMERR", 2: "SERVFAIL", 4: "NOTIMP", 5: "REFUSED" };

  /**
   * The name to ask for. A name with an address gets a random label of its
   * own in front (x3k9q2.192-168-1-10.ipssl.cc). Words in front of the
   * address do not change the answer, but no resolver has this name cached,
   * so Cloudflare has to ask ns1–4 and the check proves they answer. The
   * label starts with "x", so it never reads as an address itself.
   */
  function queryName(name, ip) {
    if (!ip) return name;
    const abc = "abcdefghijklmnopqrstuvwxyz0123456789";
    const label = `x${[...crypto.getRandomValues(new Uint8Array(5))].map((b) => abc[b % abc.length]).join("")}`;
    const q = `${label}.${name}`;
    return q.length <= MAX_NAME ? q : name;
  }

  async function check() {
    if (!target) return;
    const seq = ++checkSeq;
    const { name, ip } = target;
    const type = ip && ip.v === 6 ? "AAAA" : "A";
    const want = ip ? ipText(ip) : null;
    result = { phase: "run" };
    renderAnswer();
    checkBtn.disabled = true;

    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), CHECK_TIMEOUT_MS);
    let next;
    try {
      const url = `${DOH}?name=${encodeURIComponent(queryName(name, ip))}&type=${type}`;
      const res = await fetch(url, { headers: { accept: "application/dns-json" }, signal: ctl.signal, cache: "no-store" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      const code = type === "A" ? 1 : 28;
      const records = (body.Answer || []).filter((rr) => rr.type === code);
      if (body.Status === 3) {
        next = { phase: "bad", kind: "nx" };
      } else if (body.Status !== 0) {
        next = { phase: "bad", kind: "rcode", rcode: RCODES[body.Status] ?? `RCODE ${body.Status}` };
      } else if (!records.length) {
        // An empty answer is what a name without an address should get.
        next = { phase: want ? "bad" : "info", kind: "nodata", type };
      } else {
        const norm = (d) => (type === "A" ? d : ipText({ v: 6, a: parseV6(d, true) || [] }));
        const got = records.map((rr) => norm(rr.data));
        // Every address must be the expected one: a client may pick any of them.
        const ok = want ? got.every((g) => g === want) : null;
        next = { phase: want ? (ok ? "ok" : "bad") : "info", kind: "records", type, got, ttl: records[0].TTL, want, ok };
      }
    } catch {
      next = { phase: "bad", kind: "error", type, name };
    } finally {
      clearTimeout(timer);
    }
    // A newer input or check has taken over; this answer is for an old name.
    if (seq !== checkSeq) return;
    result = next;
    renderAnswer();
    checkBtn.disabled = false;
  }

  /** The check's path and answer, drawn from `result`. */
  function renderAnswer() {
    trace.hidden = !result;
    trace.dataset.state = result ? result.phase : "idle";
    answer.dataset.state = result && result.phase !== "run" ? result.phase : "";
    answer.innerHTML = result ? answerHtml(result) : "";
  }

  function answerHtml(res) {
    if (res.phase === "run") return escapeHtml(t("checking"));
    if (res.kind === "nx") return escapeHtml(t("nx"));
    if (res.kind === "rcode") return escapeHtml(t("rcode", { rcode: res.rcode }));
    if (res.kind === "nodata") return escapeHtml(t("nodata", { type: res.type }));
    if (res.kind === "error") return escapeHtml(t("error", { type: res.type, name: res.name }));
    const shown = res.got.map((g) => `<code>${res.type} ${escapeHtml(g)}</code>`).join(" ");
    const ttl = `<span>${escapeHtml(t("ttl", { ttl: res.ttl }))}</span>`;
    if (!res.want) return shown + ttl;
    const verdict = res.ok
      ? `${ICON_CHECK}${escapeHtml(t("match"))}`
      : `${ICON_X}${escapeHtml(t(res.got.includes(res.want) ? "mismatchOnly" : "mismatch", { want: res.want }))}`;
    return `${shown}${ttl}<span class="verdict">${verdict}</span>`;
  }

  // ---------------------------------------------------------------------
  // Copy buttons

  /** Fallback for browsers without the async clipboard API; true if it copied. */
  function legacyCopy(text) {
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.append(area);
    area.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch {
      ok = false;
    }
    area.remove();
    return ok;
  }

  const copyTimers = new WeakMap();

  /** Copies, then shows on the button whether it worked. */
  async function copyText(text, btn) {
    let ok = true;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      ok = legacyCopy(text);
    }
    // Keep the button's own label across quick repeated clicks.
    if (!copyTimers.has(btn)) btn.dataset.label = btn.getAttribute("aria-label") ?? "";
    clearTimeout(copyTimers.get(btn));
    btn.dataset.copied = ok ? "ok" : "fail";
    btn.innerHTML = ok ? ICON_CHECK : ICON_X;
    btn.setAttribute("aria-label", t(ok ? "copied" : "copyFailed"));
    if (ok) btn.removeAttribute("title");
    else btn.title = t("copyFailed");
    copyTimers.set(
      btn,
      setTimeout(
        () => {
          copyTimers.delete(btn);
          delete btn.dataset.copied;
          btn.innerHTML = ICON_COPY;
          btn.setAttribute("aria-label", btn.dataset.label);
          btn.removeAttribute("title");
        },
        ok ? 1400 : 3200,
      ),
    );
  }

  barCopy.addEventListener("click", () => {
    if (target) copyText(target.name, barCopy);
  });

  $("#ai-copy").addEventListener("click", (e) => copyText(aiPrompt.textContent, e.currentTarget));

  formsBody.addEventListener("click", (e) => {
    const btn = e.target.closest(".copy");
    if (btn) copyText(btn.dataset.copy, btn);
  });

  document.querySelectorAll("[data-copy-snip]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const lines = btn.closest(".code-panel").querySelectorAll(".snip:not([hidden]) pre:not([hidden]) .ln");
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

  document.querySelectorAll(".code-panel").forEach((panel) => {
    const tabs = [...panel.querySelectorAll('[role="tablist"] [role="tab"]')];
    // Some clients have one command per situation (port 80 free, or nginx
    // already on it); the switch picks one, and the copy button copies it.
    const modes = panel.querySelector(".modes");
    const showMode = () => {
      if (!modes) return;
      const mode = panel.dataset.mode;
      modes.querySelectorAll("[data-mode]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.mode === mode)));
      panel.querySelectorAll("pre[data-mode]").forEach((pre) => {
        pre.hidden = pre.dataset.mode !== mode;
      });
      modes.hidden = !panel.querySelector(".snip:not([hidden]) pre[data-mode]");
    };
    modes?.querySelectorAll("[data-mode]").forEach((b) => {
      b.addEventListener("click", () => {
        panel.dataset.mode = b.dataset.mode;
        showMode();
      });
    });
    const select = (tab, focus) => {
      tabs.forEach((other) => {
        const on = other === tab;
        other.setAttribute("aria-selected", String(on));
        other.tabIndex = on ? 0 : -1;
        document.getElementById(other.getAttribute("aria-controls")).hidden = !on;
      });
      showMode();
      if (focus) tab.focus();
    };
    showMode();
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

  // The IPv4 / IPv6 switch shows the other family without touching the bar.
  familyTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      family = Number(tab.dataset.family);
      renderNames();
    });
    tab.addEventListener("keydown", (e) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
      e.preventDefault();
      if (e.key === "Home") family = 4;
      else if (e.key === "End") family = 6;
      else family = family === 4 ? 6 : 4;
      renderNames();
      familyTabs.find((t) => Number(t.dataset.family) === family).focus();
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
    document.querySelectorAll(".modes").forEach((m) => m.setAttribute("aria-label", t("modes")));
    if (save) {
      try {
        localStorage.setItem("lang", lang);
      } catch {
        /* storage may be blocked; the choice just won't be remembered */
      }
    }
    // Only the words change: a check result, or one still running, stays.
    render();
  }

  langBtn.addEventListener("click", () => setLang(lang === "zh" ? "en" : "zh", true));

  // ---------------------------------------------------------------------
  // Wire up

  input.addEventListener("input", update);
  input.addEventListener("blur", commit);
  input.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" || e.isComposing) return;
    e.preventDefault();
    // Enter turns a typed address into its name; on a name, it runs the check.
    if (!commit()) check();
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
  update();
  setLang(saved === "zh" ? "zh" : "en", false);
})();
