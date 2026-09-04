# Open Source Diagnostic, Infrastructure & Agent Project Catalog v0.1

**Repository:** `caotiensinh/3agent`  
**Project:** WorkSpace  
**Last reviewed:** 2026-09-04 JST  

Mục tiêu của catalog này là tập hợp các dự án mã nguồn mở đáng nghiên cứu hoặc có thể dùng trực tiếp cho: điều tra sự cố mạng, router/switch/firewall, PC/laptop/hardware, camera/RTSP/ONVIF, DFIR/endpoint, monitoring/RCA, IP-KVM, sơ đồ kiến trúc, agent/harness và edge AI.

> Đây là **capability catalog**, không phải giấy phép copy code. Trước khi tái sử dụng source/binary phải pin đúng revision và kiểm tra `LICENSE`, third-party notices, security/dependency và điều kiện redistribution của upstream.

## Quy ước ưu tiên

- **P0** — ưu tiên nghiên cứu/dùng trước, sát trực tiếp WorkSpace/CameraOps/IP-KVM hiện tại.
- **P1** — lớp bổ sung quan trọng hoặc capability chuyên sâu.
- **P2** — reference/lab/UX; chưa cần trở thành dependency lõi.
- **Dùng thẳng** — chạy upstream như external component/adapter khi policy cho phép.
- **Chiết xuất** — học kiến trúc/schema/workflow/algorithm, không copy nguyên dự án.

## Hướng kiến trúc chung

```text
Network / Router / Endpoint / Camera / KVM
                  |
                  v
          Evidence Collectors
                  |
                  v
       Normalization + Inventory
                  |
                  v
       Correlation + Timeline
                  |
                  v
              RCA Engine
                  |
                  v
            AI Analyst / Agent
                  |
                  v
       Human-approved Actions
```

Nguyên tắc: **adapter-first**. Upstream tool là provider của evidence/capability; WorkSpace giữ schema chuẩn, permission boundary, audit và correlation.

---

# 1. Network / Packet / Traffic Investigation

| Project | Link | Cái nổi bật | Dùng thẳng vào | Phù hợp | Ghi chú |
|---|---|---|---|---|---|
| **Wireshark** | https://github.com/wireshark/wireshark | Packet/protocol forensic analyzer, decode sâu, display filter, PCAP, expert info | Mở PCAP, xác định retransmission/reset/handshake/DNS/TLS/RTSP/RTP lỗi | WorkSpace Network Analyst, CameraOps | **P0**. Ưu tiên `tshark`/PCAP evidence pipeline thay vì phụ thuộc GUI |
| **Zeek** | https://github.com/zeek/zeek | Biến network traffic thành structured logs/events như conn, DNS, HTTP, TLS, files | Sensor tạo evidence có cấu trúc cho correlation/AI | WorkSpace Network/Security Analyst | **P0**. Rất phù hợp làm nguồn event chuẩn hóa thay vì bắt AI đọc raw packet mọi lúc |
| **Suricata** | https://github.com/OISF/suricata | IDS/IPS/NSM, rule engine, flow/protocol metadata, EVE JSON | Feed alerts/flows/EVE JSON vào WorkSpace | Security Monitoring / DFIR | **P0/P1**. Detect mặc định; remediation/block phải qua approval |
| **Arkime** | https://github.com/arkime/arkime | Full packet capture + index + session search | Từ alert/event quay lại session/packet gốc | Network Forensics | **P1**. Cần storage/retention/capacity design trước khi scale |
| **ntopng** | https://github.com/ntop/ntopng | Flow/conversation, top talkers, application traffic, NetFlow/sFlow/IPFIX ecosystem | Quan sát ai dùng bandwidth và traffic behavior | WorkSpace Monitoring, SuperConnect QoS | **P1**. Kiểm tra ranh giới Community/Enterprise trước khi reuse feature |
| **Netshoot** | https://github.com/nicolaka/netshoot | Toolbox đóng gói tcpdump/dig/curl/mtr/iperf và nhiều utility | Diagnostic container/toolbox reproducible | WorkSpace Diagnostic Runner | **P0**. Học cách đóng gói toolset điều tra an toàn, có timeout |
| **iperf3** | https://github.com/esnet/iperf | TCP/UDP throughput, jitter/loss, parallel streams | Đo bandwidth thực tế giữa site/node | SuperConnect, Camera bandwidth | **P0**. Evidence phải lưu endpoint/protocol/duration/timestamp |
| **mtr** | https://github.com/traviscross/mtr | Ping + traceroute, latency/loss theo hop | Phân biệt LAN/ISP/transit/destination issue | WAN/VPN RCA | **P0**. Không kết luận loss chỉ từ 1 hop nếu các hop sau vẫn bình thường |

---

# 2. Router / Switch / Firewall Investigation

| Project | Link | Cái nổi bật | Dùng thẳng vào | Phù hợp | Ghi chú |
|---|---|---|---|---|---|
| **Batfish** | https://github.com/batfish/batfish | Static network configuration analysis, reachability/policy reasoning, what-if validation | Kiểm tra route/ACL/BGP/policy trước thay đổi | WorkSpace Network Config Analyzer | **P0**. Nền tảng tư tưởng tốt cho Network Digital Twin/pre-change validation |
| **Oxidized** | https://github.com/ytti/oxidized | Backup/version config nhiều network OS, Git/diff, event trigger | Lưu history running-config và tìm thay đổi trước incident | WorkSpace RCA | **P0**. Ghép config diff + syslog + timeline để tìm candidate root cause |
| **LibreNMS** | https://github.com/librenms/librenms | SNMP monitoring, discovery, alerting, topology, device health | Interface counters, CRC/errors/discards, temp/fan/PSU, uptime, LLDP | Router/Switch Monitoring | **P0**. Đặc biệt hữu ích với Cisco SMB/CBS và SNMP devices |
| **Prometheus snmp_exporter** | https://github.com/prometheus/snmp_exporter | Chuyển SNMP thành Prometheus metrics, generator theo MIB/module | Scrape router/switch vào metric pipeline | WorkSpace Metrics | **P0/P1**. Tốt cho metric-first architecture độc lập UI |
| **NAPALM** | https://github.com/napalm-automation/napalm | API Python thống nhất cho nhiều network OS, getters/config compare/merge/replace | Multi-vendor adapter layer | WorkSpace Network Automation | **P0**. Write/config action phải dry-run + explicit approval |
| **Nornir** | https://github.com/nornir-automation/nornir | Inventory + task orchestration + parallel execution | Read-only collection/validation trên fleet devices | WorkSpace Fleet Automation | **P1**. Command allowlist, timeout, evidence log, concurrency limit |
| **NetBox** | https://github.com/netbox-community/netbox | DCIM/IPAM/source-of-truth cho sites/devices/interfaces/IP/cables | Asset identity + topology + inventory authority | WorkSpace Inventory | **P0**. AI không được tự biến log thành asset thật nếu inventory chưa xác nhận |
| **OpenWrt** | https://github.com/openwrt/openwrt | Router Linux distribution, network/firewall/routing/package ecosystem | Lab/reference router internals | Router/Edge Lab | **P2**. Học diagnostics/ubus/netifd/firewall; không nhúng nguyên OS |
| **FRRouting** | https://github.com/FRRouting/frr | BGP/OSPF/IS-IS/RIP/PIM production routing suite | Lab routing state, test fixtures và routing RCA semantics | WorkSpace Routing Analyst | **P1/P2**. Giá trị lớn ở protocol semantics/test scenarios |

---

# 3. PC / Laptop / Hardware Diagnostics

| Project | Link | Cái nổi bật | Dùng thẳng vào | Phù hợp | Ghi chú |
|---|---|---|---|---|---|
| **smartmontools** | https://github.com/smartmontools/smartmontools | SMART health cho ATA/SATA/SAS/SCSI/NVMe; `smartctl`, `smartd` | SSD/HDD/NVMe health, temperature, wear, media/error counters, self-test | Endpoint Diagnostic, Ubuntu installer | **P0**. Chuẩn hóa typed evidence, không chỉ đọc một cờ `PASSED` |
| **Memtest86+** | https://github.com/memtest86plus/memtest86plus | Standalone RAM tester chạy ngoài OS | Xác minh RAM khi random crash/kernel panic/corruption/segfault | PC/Laptop Diagnostic | **P0/P1**. Offline workflow; agent chỉ hướng dẫn/ghi evidence, không tự reboot nếu chưa duyệt |
| **LibreHardwareMonitor** | https://github.com/LibreHardwareMonitor/LibreHardwareMonitor | CPU/GPU/mainboard/storage sensor; temp/fan/voltage/clock/load; .NET library | Windows hardware telemetry collector | WorkSpace Windows Agent | **P0**. Hợp Windows, tránh GUI scraping |
| **hw-probe** | https://github.com/linuxhw/hw-probe | Hardware probe, driver/device operability, logs, test/benchmark | Ubuntu diagnostic report: device/driver/failure/limited/malfunction | `install_ubuntuPC`, WorkSpace | **P0**. Với doanh nghiệp ưu tiên local evidence, tránh tự upload public probe |
| **stress-ng** | https://github.com/ColinIanKing/stress-ng | Stress CPU/RAM/VM/I/O/scheduler/kernel subsystems | Controlled stability/reproduction test | Ubuntu/PC Diagnostic | **P1**. Phải explicit approval, thermal guard, timeout; không tự stress production |
| **Hardinfo2** | https://github.com/hardinfo2/hardinfo2 | Linux hardware/software inventory + benchmark/report | Tool phụ/reference cho field report | Ubuntu Diagnostic | **P2**. Không cần core nếu hw-probe/native collectors đã đủ |
| **Netdata** | https://github.com/netdata/netdata | Per-second telemetry và realtime host visibility | Chứng minh CPU/RAM/disk/network/process đổi đúng lúc camera/network lag | Monitoring/RCA | **P0/P1**. Dùng time-aligned evidence, có retention/resource budget |
| **osquery** | https://github.com/osquery/osquery | Endpoint state thành SQL-like tables: process, ports, users, packages, interfaces, system | Read-only structured evidence collector Windows/Linux/macOS | Endpoint/Security Analyst | **P0**. Query allowlist + cost limit + no arbitrary shell |
| **Velociraptor** | https://github.com/Velocidex/velociraptor | DFIR fleet collection/hunting bằng VQL/artifacts | Deep incident evidence khi osquery/monitoring chưa đủ | WorkSpace DFIR | **P0/P1**. Quyền rất mạnh; phải có DFIR permission boundary/audit |

---

# 4. Camera / RTSP / ONVIF / Video Investigation

| Project | Link | Cái nổi bật | Dùng thẳng vào | Phù hợp | Ghi chú |
|---|---|---|---|---|---|
| **MediaMTX** | https://github.com/bluenviron/mediamtx | RTSP/WebRTC/HLS/SRT/RTMP/RTP proxy/server, recording/playback, protocol bridge | Camera transport/proxy + stream observation | CameraOps, RTSP Stabilizer, Edge Video Mesh | **P0**. Thu status/reconnect/readers/source metrics thành evidence |
| **go2rtc** | https://github.com/AlexxIT/go2rtc | Camera proxy/bridge RTSP/WebRTC, thực tế hữu ích với camera/RTSP implementation khó tính | Tách lỗi source camera khỏi viewer/application | CameraOps Diagnostic | **P0**. Dùng như independent adapter/test layer |
| **FFmpeg / ffprobe** | https://github.com/FFmpeg/FFmpeg | Codec/media toolkit; `ffprobe` đọc resolution/FPS/bitrate/timestamps/streams/metadata | Probe RTSP/video thành machine-readable evidence | CameraOps/VMS/Recorder | **P0**. Command phải timeout để camera chết không làm job treo vô hạn |
| **GStreamer** | https://github.com/GStreamer/gstreamer | Modular media pipeline, debug theo element/protocol stage | Định vị lỗi `rtspsrc -> RTP -> depay -> decoder -> sink` | Camera Deep Diagnostic | **P1**. Dùng khi FFmpeg/MediaMTX chưa giải thích đủ |
| **python-onvif-zeep** | https://github.com/FalkTannhaeuser/python-onvif-zeep | Python ONVIF device/media/PTZ/service client | Discover device info/profiles/stream URI/encoder/PTZ/auth error | CameraOps Inventory/Diagnostic | **P0**. Read-only mặc định; config/PTZ write qua permission gate |
| **ZoneMinder** | https://github.com/ZoneMinder/zoneminder | Mature Linux NVR/surveillance stack: capture/monitor/events/zones | Reference NVR/event/camera management workflows | CameraOps/VMS | **P2**. Không cần tích hợp nguyên stack |
| **motionEye** | https://github.com/motioneye-project/motioneye | Web camera management đơn giản quanh Motion | UX/configuration reference cho field deployment | CameraOps UI | **P2**. Giá trị ở simplicity |
| **Frigate** | https://github.com/blakeblackshear/frigate | Local NVR + realtime object detection/event pipeline + hardware acceleration | Reference event lifecycle, recording, camera health, accelerator architecture | CameraOps AI/Bear Detection/VMS | **P0/P1**. Học architecture/event model, không copy nguyên nếu lệch enterprise design |

---

# 5. User-added projects — Diagram / IP-KVM / Dev Platform / Agent / Edge AI

## 5.1 drawio-mcp

- **Tên:** `jgraph/drawio-mcp`
- **Link:** https://github.com/jgraph/drawio-mcp
- **License:** Apache-2.0.
- **Cái nổi bật:** official draw.io MCP; có **MCP App Server**, **MCP Tool Server**, plugin cho Claude Code/Codex CLI/GitHub Copilot; tạo/open editable draw.io; hỗ trợ XML/CSV/Mermaid tùy mode; tìm **10,000+ shapes**; có ELK/libavoid layout/routing.
- **Dùng thẳng vào:** AI tạo sơ đồ network topology, architecture, incident flow, rack/camera/KVM topology rồi mở lại bằng draw.io để chỉnh sửa.
- **Điểm rất hợp WorkSpace:** có thể dùng local/self-host để giảm rò rỉ dữ liệu; thích hợp biến inventory + correlation + RCA thành sơ đồ tự động.
- **Ghi chú:** **P0**. Với dữ liệu nội bộ ưu tiên MCP Tool/local plugin hoặc self-host App Server, không mặc định gửi diagram lên hosted endpoint.

## 5.2 BliKVM

- **Tên:** `blikvm/blikvm`
- **Link:** https://github.com/blikvm/blikvm
- **License:** GPL-3.0.
- **Cái nổi bật:** open/cost-effective KVM-over-IP; nhiều hardware model; HDMI/ATX/remote console ecosystem.
- **Dùng thẳng vào:** backend/device target cho `IP_KVM_Managerment_system`; remote recovery khi OS/network software của target không còn hoạt động.
- **Điểm rất hợp:** bạn đang dùng BliKVM thực tế, vì vậy nên xây adapter ổn định cho health/video/input/power/device identity.
- **Ghi chú:** **P0**. Không fork sâu nếu chưa cần; ưu tiên API/adapter và compatibility test.

## 5.3 PiKVM

- **Tên:** `pikvm/pikvm`
- **Link:** https://github.com/pikvm/pikvm
- **License:** GPL-3.0.
- **Cái nổi bật:** mature Raspberry Pi IP-KVM ecosystem; video capture, keyboard/mouse, ATX control, virtual media và remote management.
- **Dùng thẳng vào:** compatibility/reference backend và baseline capability để so sánh BliKVM.
- **Điểm rất hợp:** giúp định nghĩa **canonical KVM capability interface** cho WorkSpace/IP-KVM Central.
- **Ghi chú:** **P0/P1**. BliKVM/PiKVM/TinyPilot phải vào cùng abstraction layer, không tạo UI logic riêng từng vendor.

## 5.4 TinyPilot

- **Tên:** `tiny-pilot/tinypilot`
- **Link:** https://github.com/tiny-pilot/tinypilot
- **License:** MIT.
- **Cái nổi bật:** browser-based Raspberry Pi KVM; Python codebase và kiến trúc tương đối dễ đọc/học.
- **Dùng thẳng vào:** reference/compatibility target cho browser KVM và remote recovery.
- **Điểm rất hợp:** học simplicity, UX và luồng video/input; dùng để kiểm tra abstraction có quá phụ thuộc PiKVM/BliKVM không.
- **Ghi chú:** **P1**.

## 5.5 Harness Open Source

- **Tên:** `harness/harness`
- **Link:** https://github.com/harness/harness
- **License:** Apache-2.0.
- **Cái nổi bật:** end-to-end developer platform gồm Source Control Management, CI/CD pipelines, hosted developer environments và artifact registries.
- **Dùng thẳng vào:** reference cho pipeline execution, artifacts, CI/CD governance, developer platform và release automation.
- **Ghi chú cực quan trọng:** **KHÔNG phải Harness Agent** chúng ta đang thiết kế. `harness/harness` là developer platform; WorkSpace Harness Agent là reasoning/knowledge/problem-solving loop.
- **Ưu tiên:** **P1** — học governance/execution patterns, không nhập nhằng hai kiến trúc.

## 5.6 PicoLM

- **Tên:** `RightNow-AI/picolm`
- **Link:** https://github.com/RightNow-AI/picolm
- **License:** MIT.
- **Cái nổi bật:** minimal C11 LLM inference engine, zero dependencies, khoảng **80 KB binary**, khoảng **45 MB runtime RAM**, model stays on disk qua `mmap`, hỗ trợ GGUF/K-quants, ARM/x86/RISC-V, constrained JSON/tool calling.
- **Thông số mẫu upstream:** TinyLlama 1.1B Q4_K_M khoảng **638 MB model**; Raspberry Pi 4 được upstream báo khoảng ~8 tok/s tùy điều kiện.
- **Dùng thẳng vào:** edge/offline diagnostic assistant trên mini-PC/Raspberry Pi/low-memory node; local brain cho structured tool selection đơn giản.
- **Điểm đáng chiết xuất:** mmap layer streaming, low-RAM KV/cache strategy, zero-dependency runtime, grammar-constrained JSON.
- **Ghi chú:** **P0 research**. Model 1B không nên tự làm RCA phức tạp; phù hợp classifier/router/tool selector/field helper hơn.

## 5.7 Hermes-Agent

- **Tên:** `NousResearch/hermes-agent`
- **Link:** https://github.com/NousResearch/hermes-agent
- **License:** MIT.
- **Cái nổi bật:** self-improving agent với closed learning loop; memory bền vững; tự tạo/cải thiện skills từ experience; session search; cron scheduler; delegates/subagents; nhiều terminal backend; MCP/tool integrations; nhiều messaging channel.
- **Dùng thẳng vào:** **reference trực tiếp cho WorkSpace Harness Agent**: memory lifecycle, skill lifecycle, learning loop, cross-session recall, subagent delegation và scheduled automation.
- **Điểm đáng chiết xuất:** agent-curated memory, skill improvement during use, persistent knowledge nudges, isolated subagents, tool RPC và command/security model.
- **Ghi chú:** **P0 research**. Không copy nguyên agent; mọi pattern phải được benchmark/evidence và đưa qua permission/security gate của WorkSpace.

## 5.8 OpenClaw

- **Tên:** `openclaw/openclaw`
- **Link:** https://github.com/openclaw/openclaw
- **License:** **MIT**, xác minh trực tiếp từ file `LICENSE` của repository. GitHub REST metadata hiện có thể trả `NOASSERTION`, nên không dùng field metadata đó làm nguồn cuối cùng.
- **Cái nổi bật:** assistant gateway chạy trên thiết bị của người dùng; kết nối model/tools/channels/plugins/skills/device nodes qua một Gateway; có Control UI/CLI/TUI; local + hosted providers; companion/device actions.
- **Security idea đáng học:** trusted gateway + untrusted execution + deterministic policy; inbound message phải xem là untrusted; có pairing và sandboxing guidance.
- **Dùng thẳng vào:** reference mạnh cho Agent Gateway, channel adapter, plugin/skill lifecycle, device node, pairing/auth và sandbox architecture.
- **Ghi chú:** **P0 research**. Không nối inbound chat trực tiếp vào shell/network/config/power actions khi chưa qua pairing/RBAC/approval.

---

# 6. Priority shortlist cho các dự án hiện tại

## P0 — Network / Security / RCA

1. **Zeek** — structured network evidence.
2. **Batfish** — config reasoning / pre-change validation.
3. **LibreNMS + snmp_exporter** — router/switch health và interface metrics.
4. **Oxidized** — config history/diff cho incident timeline.
5. **Wireshark/tshark** — packet-level ground truth.
6. **Suricata** — security/flow event.
7. **osquery** — structured endpoint evidence.
8. **smartmontools + hw-probe + LibreHardwareMonitor** — hardware evidence.
9. **Netdata** — time-aligned host performance evidence.
10. **MediaMTX + go2rtc + ffprobe + ONVIF** — camera/stream evidence.

## P0 — IP-KVM / Remote Recovery

1. **BliKVM** — current real backend.
2. **PiKVM** — mature reference baseline.
3. **TinyPilot** — simplicity/UX reference.
4. Xây **một KVM Capability Adapter** để chuẩn hóa video/input/power/virtual-media/health thay vì code UI riêng theo vendor.

## P0 — Harness / Agent evolution

1. **Hermes-Agent** — learning loop, skills, memory, subagents, cron.
2. **OpenClaw** — gateway, channels, tools/plugins, device nodes, sandbox/policy.
3. **PicoLM** — low-RAM edge inference + constrained JSON.
4. **drawio-mcp** — editable diagrams từ topology/evidence/RCA.
5. **Harness Open Source** — CI/CD/artifact governance reference, **không phải Harness Agent**.

---

# 7. Capability extraction map

| WorkSpace capability | Upstream reference chính |
|---|---|
| Packet Evidence | Wireshark/tshark, Arkime |
| Network Event Evidence | Zeek, Suricata |
| Flow/Bandwidth Evidence | ntopng, iperf3, mtr |
| Router/Switch Telemetry | LibreNMS, snmp_exporter |
| Config History | Oxidized |
| Config Reasoning | Batfish |
| Multi-vendor Network Adapter | NAPALM, Nornir |
| Inventory / Source of Truth | NetBox |
| Endpoint Evidence | osquery, Velociraptor |
| Disk/NVMe Health | smartmontools |
| Linux Hardware | hw-probe, stress-ng |
| Windows Hardware | LibreHardwareMonitor |
| Realtime Host RCA | Netdata |
| Camera Transport | MediaMTX, go2rtc |
| Camera Probe | FFmpeg/ffprobe, GStreamer |
| Camera Capability | python-onvif-zeep |
| NVR/Event Reference | Frigate, ZoneMinder |
| IP-KVM Backends | BliKVM, PiKVM, TinyPilot |
| AI Diagram Generation | drawio-mcp |
| Agent Learning/Memory | Hermes-Agent |
| Agent Gateway/Tools/Channels | OpenClaw |
| Tiny Edge LLM | PicoLM |
| CI/CD/Artifact Governance | Harness Open Source |

---

# 8. Enterprise guardrails trước khi adopt upstream

1. **License gate:** pin exact revision; đọc `LICENSE` + third-party notices trước khi copy/repackage.
2. **Security gate:** dependency/SBOM/malware scan; không chạy remote install script trên production khi chưa review.
3. **Permission gate:** collector mặc định read-only; config write/reboot/power/PTZ/firewall/remediation/stress test cần explicit authorization.
4. **Evidence gate:** mọi diagnostic action phải ghi target, timestamp, command/API, result, exit status, correlation ID và hash khi phù hợp.
5. **Resource gate:** timeout + CPU/RAM/network/storage limits; PCAP/stress test phải bounded duration/size.
6. **Privacy gate:** không tự upload log/PCAP/hardware/camera evidence của doanh nghiệp lên public upstream service.
7. **Integration rule:** ưu tiên adapter/API/CLI invocation hơn vendoring/copy một codebase lớn.
8. **Canonical module rule:** một WorkSpace capability sở hữu schema chuẩn; upstream tools chỉ là provider.

# 9. Next review targets

Với từng project **P0**, lần review tiếp theo cần ghi thêm:

- exact upstream version/SHA;
- license status;
- supported OS/hardware;
- API/CLI interface;
- machine-readable output/schema;
- privilege requirement;
- deployment footprint;
- security risks;
- test fixture strategy;
- WorkSpace adapter/schema sẽ consume nó;
- PASS/REJECT/REFERENCE_ONLY decision.
