import httpx

OLLAMA_BASE = "http://192.168.52.48:11434"
DEFAULT_MODEL = "qwen-claude:latest"
TIMEOUT = 120
LONG_TIMEOUT = 600


async def list_models() -> list[str]:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(f"{OLLAMA_BASE}/api/tags")
        r.raise_for_status()
        return [m["name"] for m in r.json().get("models", [])]


async def generate(prompt: str, model: str = DEFAULT_MODEL, system: str = "",
                   timeout: int = TIMEOUT) -> str:
    payload = {"model": model, "prompt": prompt, "stream": False}
    if system:
        payload["system"] = system
    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.post(f"{OLLAMA_BASE}/api/generate", json=payload)
        r.raise_for_status()
        return r.json().get("response", "")


async def chat(messages: list[dict], model: str = DEFAULT_MODEL) -> str:
    payload = {"model": model, "messages": messages, "stream": False}
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        r = await client.post(f"{OLLAMA_BASE}/api/chat", json=payload)
        r.raise_for_status()
        return r.json().get("message", {}).get("content", "")


def build_host_prompt(host: dict, ports: list[dict],
                      services: list[dict] | None = None,
                      connections: list[dict] | None = None) -> str:
    port_lines = "\n".join(
        f"  {p['port']}/{p['protocol']}  {p['service'] or '?'}  {p['version'] or ''}"
        + ("  [manual]" if p.get("manual") else "")
        for p in ports
    ) or "  none detected"

    svc_lines = ""
    if services:
        svc_lines = "\nRegistered services:\n" + "\n".join(
            f"  {s['name']}  port={s.get('port') or '?'}/{s.get('protocol','tcp')}"
            f"  status={s.get('status','unknown')}"
            + (f"  url={s['url']}" if s.get('url') else "")
            + (f"  — {s['description']}" if s.get('description') else "")
            for s in services
        )

    conn_lines = ""
    if connections:
        conn_lines = "\nConnections:\n" + "\n".join(
            f"  ↔ {c['peer_ip']}"
            + (f" ({c['peer_label']})" if c.get('peer_label') else "")
            + (f"  {c['speed']}" if c.get('speed') else "")
            + (f"  mode={c['port_mode']}" if c.get('port_mode') else "")
            + (f"  vlans={c['vlan_summary']}" if c.get('vlan_summary') else "")
            + (f"  [{c['label']}]" if c.get('label') else "")
            for c in connections
        )

    meta = []
    if host.get('device_type') and host['device_type'] != 'unknown':
        meta.append(f"Device type: {host['device_type']}")
    if host.get('port_count') and host['port_count'] > 1:
        meta.append(f"Physical ports: {host['port_count']}")
    if host.get('has_wifi'):
        meta.append("Has WiFi capability")
    if host.get('notes'):
        meta.append(f"Notes: {host['notes']}")
    meta_lines = ("\n" + "\n".join(meta)) if meta else ""

    return f"""Analyze this network host and give a practical assessment.

IP: {host['ip']}
Hostname: {host.get('hostname') or 'unknown'}
MAC: {host.get('mac') or 'unknown'}
Vendor: {host.get('vendor') or 'unknown'}
OS: {host.get('os_guess') or 'unknown'}{meta_lines}

Open ports:
{port_lines}{svc_lines}{conn_lines}

Answer in 4-6 sentences covering:
1. What type of device this is and its role in the network
2. What services it provides (scanned ports + registered services)
3. How it fits into the network topology (connections, VLANs, speed)
4. Any notable security observations or recommendations"""


def build_network_prompt(hosts: list[dict], connections: list[dict],
                         vlans: list[dict], subnets: list[dict]) -> str:
    subnet_lines = "\n".join(
        f"  {s['cidr']}  {s['name']}" + (f" — {s['description']}" if s.get('description') else "")
        for s in subnets
    ) or "  none defined"

    vlan_lines = "\n".join(
        f"  VLAN {v['tag']}  {v['name']}  color={v['color']}"
        for v in vlans
    ) or "  none defined"

    host_lines = []
    for h in hosts:
        parts = [f"\n[{h['ip']}]"]
        if h.get('hostname'):   parts.append(f"  hostname={h['hostname']}")
        if h.get('device_type'): parts.append(f"  type={h['device_type']}")
        if h.get('vendor'):     parts.append(f"  vendor={h['vendor']}")
        if h.get('os_guess'):   parts.append(f"  os={h['os_guess']}")
        if h.get('has_wifi'):   parts.append(f"  wifi=yes")
        if h.get('port_count') and h['port_count'] > 1:
            parts.append(f"  switch_ports={h['port_count']}")
        if h.get('notes'):      parts.append(f"  notes={h['notes']}")
        if h.get('ports'):
            open_ports = [p for p in h['ports'] if p.get('state') == 'open' or p.get('manual')]
            if open_ports:
                parts.append("  open_ports: " + ", ".join(
                    f"{p['port']}/{p['protocol']}({p.get('service') or '?'})" for p in open_ports
                ))
        if h.get('services'):
            parts.append("  services: " + ", ".join(
                f"{s['name']}:{s.get('port','?')}[{s.get('status','?')}]" for s in h['services']
            ))
        host_lines.append("\n".join(parts))

    conn_lines = []
    for c in connections:
        line = f"  {c['src_ip']} ↔ {c['dst_ip']}"
        if c.get('speed'):      line += f"  {c['speed']}"
        if c.get('port_mode'):  line += f"  mode={c['port_mode']}"
        if c.get('tagged_only'): line += "  tagged-only"
        if c.get('vlans'):
            line += "  vlans=" + ",".join(f"{v['tag']}({v['name']})" for v in c['vlans'])
        if c.get('label'):      line += f"  [{c['label']}]"
        conn_lines.append(line)

    return f"""Perform a comprehensive analysis of this network.

== Subnets ==
{subnet_lines}

== VLANs ==
{vlan_lines}

== Hosts ({len(hosts)}) ==
{"".join(host_lines)}

== Connections ({len(connections)}) ==
{chr(10).join(conn_lines) or "  none defined"}

Provide a structured analysis covering:
1. TOPOLOGY OVERVIEW — describe the network structure, tiers, and key infrastructure roles
2. DEVICE ROLES — for each significant device, what it does and its importance
3. VLAN & SEGMENTATION — how the network is segmented, whether it makes sense
4. SECURITY OBSERVATIONS — exposed services, missing segmentation, risky configurations, open ports of concern
5. RECOMMENDATIONS — specific actionable improvements (redundancy, segmentation, hardening)

Be specific and reference actual IPs, hostnames, and port numbers from the data above."""


def infer_device_type(analysis: str) -> str:
    lower = analysis.lower()
    if "access point" in lower or " ap " in lower:
        return "ap"
    for dtype in ["router", "gateway", "switch", "firewall", "server", "nas",
                  "container", "vm", "printer", "camera", "iot",
                  "workstation", "laptop", "phone", "tablet"]:
        if dtype in lower:
            return dtype
    return "unknown"
