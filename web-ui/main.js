// ═══════════════════════════════════════════════════════════════════════════
// OWL MONITOR — ADVANCED SOC DASHBOARD CLIENT
// Strict real-data integration, safe rendering, and forensic investigation
// ═══════════════════════════════════════════════════════════════════════════

(function () {
    "use strict";

    // ── Application State ────────────────────────────────────────────────────
    const state = {
        alerts: [],              // Confirmed detection alerts (from rule engine)
        events: [],              // Normalized security events (from collectors)
        blocked_ips: [],         // Confirmed blocked IPs
        firewall_actions: [],    // Confirmed firewall actions ledger
        ti_cache: {},            // ip -> threat intelligence dossier
        fim_violations: [],      // FIM violation alerts
        network_events: [],      // Network-specific events
        proto_counts: {          // Protocol distribution counters (real packets)
            tcp: 0,
            udp: 0,
            icmp: 0,
            arp: 0,
            dns: 0,
            other: 0,
            total: 0
        },
        detection_counts: {},    // event_type -> count
        rules_catalog: [],       // Catalog of 19 capabilities
        loaded_rules: [],        // Raw YAML rules loaded from disk
        config: null,            // Sanitized system config from /api/config
        system_status: null,     // Dependency & host check from /api/system
        last_event_time: null,   // Timestamp of newest event received
        active_cat_filter: "all",
        active_severity_filter: "all",
        active_collector_filter: "all",
        search_query: "",
        sort_mode: "newest"
    };

    // ── DOM Helper ───────────────────────────────────────────────────────────
    const $ = (id) => document.getElementById(id);

    // ── Safe Text Helper (Prevents XSS) ──────────────────────────────────────
    function escapeHtml(str) {
        if (str === null || str === undefined) return "Not available";
        const div = document.createElement("div");
        div.textContent = String(str);
        return div.innerHTML;
    }

    function safeVal(val, defaultVal = "Not available") {
        if (val === null || val === undefined || val === "" || val === "N/A" || val === "unknown") {
            return defaultVal;
        }
        return String(val);
    }

    // ── WebSocket Connection & Resilience ────────────────────────────────────
    let ws = null;
    let reconnectTimer = null;

    function connectWebSocket() {
        const protocol = location.protocol === "https:" ? "wss:" : "ws:";
        const wsUrl = `${protocol}//${location.host}/ws/alerts`;

        try {
            ws = new WebSocket(wsUrl);
        } catch (e) {
            updateWsStatus(false);
            scheduleReconnect();
            return;
        }

        ws.onopen = () => {
            updateWsStatus(true);
            // Fetch state snapshot and system endpoints
            fetchInitialState();
            fetchRules();
            fetchConfig();
            fetchSystemStatus();
        };

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === "new_alert") {
                    handleNewAlert(msg.data, false);
                } else if (msg.type === "new_event") {
                    handleNewEvent(msg.data);
                } else if (msg.type === "ip_blocked") {
                    handleIpBlocked(msg.data);
                }
                recordLastEventTime();
            } catch (e) {
                console.error("WebSocket message parse error:", e);
            }
        };

        ws.onclose = () => {
            updateWsStatus(false);
            scheduleReconnect();
        };

        ws.onerror = () => {
            updateWsStatus(false);
            if (ws) ws.close();
        };
    }

    function scheduleReconnect() {
        if (!reconnectTimer) {
            reconnectTimer = setTimeout(() => {
                reconnectTimer = null;
                connectWebSocket();
            }, 3000);
        }
    }

    function updateWsStatus(connected) {
        const el = $("ws-status");
        const topBadge = $("topbar-ws-badge");
        const sysEl = $("sys-ws-status");

        if (connected) {
            if (el) el.innerHTML = '<span class="status-indicator-dot connected"></span><span class="status-indicator-text">WebSocket: Connected</span>';
            if (topBadge) {
                topBadge.className = "badge badge-success";
                topBadge.textContent = "Connected";
            }
            if (sysEl) {
                sysEl.textContent = "Connected (Streaming live)";
                sysEl.className = "color-success";
            }
        } else {
            if (el) el.innerHTML = '<span class="status-indicator-dot disconnected"></span><span class="status-indicator-text">Connection Lost</span>';
            if (topBadge) {
                topBadge.className = "badge badge-critical";
                topBadge.textContent = "Disconnected";
            }
            if (sysEl) {
                sysEl.textContent = "Connection Lost (Reconnecting…)";
                sysEl.className = "color-critical";
            }
        }
    }

    function recordLastEventTime() {
        const now = new Date();
        state.last_event_time = now;
        const timeStr = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
        const el = $("last-updated");
        if (el) el.textContent = timeStr;
    }

    // ── Initial State Fetch ──────────────────────────────────────────────────
    function fetchInitialState() {
        fetch("/api/state")
            .then((r) => {
                if (!r.ok) throw new Error("State API error");
                return r.json();
            })
            .then((data) => {
                if (data.blocked_ips && Array.isArray(data.blocked_ips)) {
                    state.blocked_ips = data.blocked_ips;
                }
                if (data.firewall_actions && Array.isArray(data.firewall_actions)) {
                    state.firewall_actions = data.firewall_actions;
                    renderFirewallActionsTable();
                }
                if (data.threat_intel && typeof data.threat_intel === "object") {
                    Object.entries(data.threat_intel).forEach(([ip, ti]) => {
                        if (ti && ti.matched) {
                            state.ti_cache[ip] = ti;
                        }
                    });
                    renderThreatIntelTable();
                }
                if (data.events && Array.isArray(data.events)) {
                    // Process historical events in reverse to maintain chronology
                    data.events.slice().reverse().forEach((ev) => handleNewEvent(ev, true));
                }
                if (data.alerts && Array.isArray(data.alerts)) {
                    data.alerts.slice().reverse().forEach((al) => handleNewAlert(al, true));
                }
                updateAllStatistics();
            })
            .catch((err) => {
                console.warn("Could not fetch /api/state snapshot:", err);
            });
    }

    function fetchRules() {
        fetch("/api/rules")
            .then((r) => r.json())
            .then((data) => {
                state.loaded_rules = data.loaded_rules || [];
                state.rules_catalog = data.capabilities || [];
                renderRulesPage();
            })
            .catch((err) => {
                console.warn("Could not fetch /api/rules:", err);
            });
    }

    function fetchConfig() {
        fetch("/api/config")
            .then((r) => r.json())
            .then((cfg) => {
                state.config = cfg;
                renderConfigValues(cfg);
            })
            .catch(() => {});
    }

    function fetchSystemStatus() {
        fetch("/api/system")
            .then((r) => r.json())
            .then((data) => {
                state.system_status = data;
                renderSystemStatus(data);
            })
            .catch(() => {});
    }

    // ── Event Ingestion Handlers ─────────────────────────────────────────────

    function handleNewAlert(alert, isBatch = false) {
        if (!alert || !alert.id) return;

        // Prevent duplicate alerts
        if (state.alerts.some((a) => a.id === alert.id)) {
            return;
        }

        state.alerts.unshift(alert);
        if (state.alerts.length > 200) state.alerts.length = 200;

        // Categorize alert into SOC categories (Section 5)
        alert.soc_category = classifyAlertCategory(alert);

        // FIM check
        const titleLower = (alert.rule_title || "").toLowerCase();
        if (titleLower.includes("file integrity") || alert.logsource === "fim") {
            if (!state.fim_violations.some((v) => v.id === alert.id)) {
                state.fim_violations.unshift(alert);
            }
            renderFIMPage();
        }

        // Threat Intel extraction
        const ti = alert.threat_intel;
        if (ti && ti.matched && alert.ip && alert.ip !== "N/A" && alert.ip !== "Unknown") {
            state.ti_cache[alert.ip] = ti;
            renderThreatIntelTable();
        }

        // Add to tables
        addAlertToOverviewTable(alert);
        renderAlertsPageTable();
        updateAllStatistics();

        if (!isBatch) {
            flashNotification();
            recordLastEventTime();
        }
    }

    function handleNewEvent(event, isBatch = false) {
        if (!event) return;

        state.events.unshift(event);
        if (state.events.length > 300) state.events.length = 300;

        // Protocol accounting (Section 8 - Protocol Distribution)
        const proto = (event.protocol || "").toUpperCase();
        const evType = (event.event_type || "").toLowerCase();

        let detectedProto = "OTHER";
        if (proto === "TCP" || evType.includes("tcp") || evType.includes("port_scan") || evType.includes("syn")) {
            detectedProto = "TCP";
            state.proto_counts.tcp++;
        } else if (proto === "UDP" || evType.includes("udp")) {
            detectedProto = "UDP";
            state.proto_counts.udp++;
        } else if (proto === "ICMP" || evType.includes("icmp") || evType.includes("ping")) {
            detectedProto = "ICMP";
            state.proto_counts.icmp++;
        } else if (proto === "ARP" || evType.includes("arp")) {
            detectedProto = "ARP";
            state.proto_counts.arp++;
        } else if (evType.includes("dns")) {
            detectedProto = "DNS";
            state.proto_counts.dns++;
        } else {
            state.proto_counts.other++;
        }
        state.proto_counts.total++;

        // Taxonomy counts
        if (evType) {
            state.detection_counts[evType] = (state.detection_counts[evType] || 0) + 1;
        }

        // If it's a network event, store in network_events list
        if (event.logsource === "network" || event.dst_ip || event.sport || event.dport) {
            event.resolved_proto = detectedProto;
            state.network_events.unshift(event);
            if (state.network_events.length > 150) state.network_events.length = 150;
            addNetworkRow(event);
        }

        // Auth event tracking
        if (event.logsource === "auth") {
            addAuthRow(event);
        }

        updateAllStatistics();
        updateProtocolDistributionUI();

        if (!isBatch) {
            recordLastEventTime();
        }
    }

    function handleIpBlocked(data) {
        if (!data || !data.ip) return;
        const ip = data.ip;
        if (!state.blocked_ips.includes(ip)) {
            state.blocked_ips.push(ip);
        }

        // Record action entry in ledger
        const entry = {
            ip: ip,
            action: data.action || "DROP",
            target: data.target || "INPUT",
            status: data.status || "Block Successful",
            timestamp: data.timestamp || new Date().toLocaleTimeString(),
            duration: data.duration || "3600s (Temporary)"
        };

        if (!state.firewall_actions.some((a) => a.ip === ip && a.timestamp === entry.timestamp)) {
            state.firewall_actions.unshift(entry);
        }

        renderFirewallActionsTable();
        updateAllStatistics();
    }

    // ── Classification Logic (Section 5 Alert Categories) ───────────────────
    function classifyAlertCategory(alert) {
        const title = (alert.rule_title || "").toLowerCase();
        const logsource = (alert.logsource || "").toLowerCase();

        if (logsource === "auth" || title.includes("ssh") || title.includes("brute") || title.includes("login") || title.includes("auth")) {
            return "Authentication Security";
        }
        if (logsource === "fim" || title.includes("file integrity") || title.includes("fim")) {
            return "File Integrity";
        }
        if (logsource === "threat_intel" || title.includes("malicious ip") || title.includes("botnet") || title.includes("reputation")) {
            return "Threat Intelligence";
        }
        if (logsource === "network" || title.includes("scan") || title.includes("flood") || title.includes("spoof") || title.includes("tunnel") || title.includes("beacon") || title.includes("packet") || title.includes("snort") || logsource === "snort") {
            return "Network Security";
        }
        return "System Security";
    }

    // ── Statistical Calculation (Strictly Real Data - Section 4) ─────────────
    function updateAllStatistics() {
        const totalEvents = state.events.length;
        const totalAlerts = state.alerts.length;

        let critCount = 0;
        let highCount = 0;
        let medCount = 0;
        let lowCount = 0;
        const uniqueIps = new Set();

        state.alerts.forEach((a) => {
            const lvl = (a.level || "").toLowerCase();
            if (lvl === "critical") critCount++;
            else if (lvl === "very high" || lvl === "high") highCount++;
            else if (lvl === "medium") medCount++;
            else lowCount++;

            if (a.ip && a.ip !== "N/A" && a.ip !== "Unknown") {
                uniqueIps.add(a.ip);
            }
        });

        state.events.forEach((e) => {
            if (e.ip && e.ip !== "N/A" && e.ip !== "Unknown") {
                uniqueIps.add(e.ip);
            }
        });

        const blockedCount = state.blocked_ips.length;

        // Overview Metric Cards
        safeSetText("metric-network-events", totalEvents.toLocaleString());
        safeSetText("metric-active-alerts", totalAlerts.toLocaleString());
        safeSetText("metric-critical-alerts", critCount.toLocaleString());
        safeSetText("metric-high-alerts", highCount.toLocaleString());
        safeSetText("metric-medium-alerts", medCount.toLocaleString());
        safeSetText("metric-low-alerts", lowCount.toLocaleString());
        safeSetText("metric-unique-ips", uniqueIps.size.toLocaleString());
        safeSetText("metric-blocked-ips", blockedCount.toLocaleString());

        // Quick Module Counters
        safeSetText("event-counter", `${totalEvents} events`);
        safeSetText("net-total", totalEvents.toLocaleString());
        safeSetText("net-blocked", blockedCount.toLocaleString());
        safeSetText("fim-modified", state.fim_violations.length.toString());

        // Threat Posture Level Calculation
        updateThreatPostureLevel(critCount, highCount, medCount);

        // Network Page Counters
        safeSetText("net-page-total", totalEvents.toLocaleString());
        safeSetText("net-count-tcp", state.proto_counts.tcp.toLocaleString());
        safeSetText("net-count-udp", state.proto_counts.udp.toLocaleString());
        safeSetText("net-count-icmp", state.proto_counts.icmp.toLocaleString());
        safeSetText("net-count-alerts", totalAlerts.toLocaleString());
        safeSetText("net-page-blocked", blockedCount.toLocaleString());

        const srcIps = new Set();
        const dstIps = new Set();
        state.network_events.forEach((ev) => {
            if (ev.ip && ev.ip !== "N/A") srcIps.add(ev.ip);
            if (ev.dst_ip && ev.dst_ip !== "N/A") dstIps.add(ev.dst_ip);
        });
        safeSetText("net-count-src-ips", srcIps.size.toLocaleString());
        safeSetText("net-count-dst-ips", dstIps.size.toLocaleString());

        // Update taxonomy counters
        updateTaxonomyCards();

        // Update Threat Intel snapshot counters
        const tiIps = Object.keys(state.ti_cache);
        safeSetText("ti-tracked-count", tiIps.length.toString());
        let malCount = 0;
        let botnetCount = 0;
        const countries = new Set();
        tiIps.forEach((ip) => {
            const ti = state.ti_cache[ip];
            if (ti.malicious_score >= 50) malCount++;
            if (ti.known_botnet) botnetCount++;
            if (ti.country && ti.country !== "Unknown") countries.add(ti.country);
        });
        safeSetText("ti-malicious-count", malCount.toString());
        safeSetText("ti-botnet-count", botnetCount.toString());
        safeSetText("ti-stat-lookups", tiIps.length.toString());
        safeSetText("ti-stat-countries", countries.size.toString());

        // FIM Page status
        safeSetText("fim-page-violations-count", state.fim_violations.length.toString());
        const fimStatusEl = $("fim-page-baseline-status");
        if (fimStatusEl) {
            if (state.fim_violations.length > 0) {
                fimStatusEl.textContent = "Violations Detected";
                fimStatusEl.className = "metric-value color-critical";
            } else {
                fimStatusEl.textContent = "Clean";
                fimStatusEl.className = "metric-value color-success";
            }
        }

        // Firewall Page count
        safeSetText("firewall-blocked-count", blockedCount.toString());
        safeSetText("firewall-actions-counter", `${state.firewall_actions.length} confirmed actions`);
    }

    function updateThreatPostureLevel(crit, high, med) {
        const badge = $("metric-threat-level");
        const title = $("posture-level-title");
        const desc = $("posture-level-desc");

        let level = "Low";
        let levelClass = "low";
        let explainer = "System operating under nominal conditions. No critical incidents detected in the active inspection window.";

        if (crit > 0) {
            level = "Critical";
            levelClass = "critical";
            explainer = `${crit} CRITICAL incident(s) detected. Host integrity violation or active high-rate attack requires immediate SOC intervention.`;
        } else if (high > 0) {
            level = "High";
            levelClass = "high";
            explainer = `${high} High-severity alert(s) detected. Automated containment mechanisms have been dispatched.`;
        } else if (med > 0) {
            level = "Medium";
            levelClass = "medium";
            explainer = `${med} Medium-severity anomaly patterns detected. System telemetry monitored for escalation.`;
        }

        if (badge) {
            badge.textContent = level;
            badge.className = `threat-level-badge ${levelClass}`;
        }
        if (title) {
            title.textContent = level;
            title.className = `color-${levelClass}`;
        }
        if (desc) {
            desc.textContent = explainer;
        }
    }

    function updateTaxonomyCards() {
        safeSetText("det-port_scan", (state.detection_counts["port_scan"] || 0).toString());
        safeSetText("det-syn_flood", (state.detection_counts["tcp_syn"] || state.detection_counts["syn_flood"] || 0).toString());
        safeSetText("det-ping_flood", (state.detection_counts["icmp_ping"] || state.detection_counts["ping_flood"] || 0).toString());
        safeSetText("det-dns_flood", (state.detection_counts["dns_query"] || state.detection_counts["dns_flood"] || 0).toString());
        safeSetText("det-arp_spoofing", (state.detection_counts["arp_spoofing"] || 0).toString());
        safeSetText("det-dns_tunneling", (state.detection_counts["dns_tunneling"] || 0).toString());
        safeSetText("det-beaconing", (state.detection_counts["beaconing"] || 0).toString());
        safeSetText("det-suspicious_packet", (state.detection_counts["suspicious_packet"] || 0).toString());
        safeSetText("det-snort_alert", (state.detection_counts["snort_alert"] || 0).toString());
    }

    function updateProtocolDistributionUI() {
        const total = state.proto_counts.total;
        if (total === 0) return;

        const tcpPct = Math.round((state.proto_counts.tcp / total) * 100);
        const udpPct = Math.round((state.proto_counts.udp / total) * 100);
        const icmpPct = Math.round((state.proto_counts.icmp / total) * 100);
        const arpPct = Math.round((state.proto_counts.arp / total) * 100);
        const dnsPct = Math.round((state.proto_counts.dns / total) * 100);
        const otherPct = Math.max(0, 100 - (tcpPct + udpPct + icmpPct + arpPct + dnsPct));

        setBarWidth("proto-seg-tcp", tcpPct);
        setBarWidth("proto-seg-udp", udpPct);
        setBarWidth("proto-seg-icmp", icmpPct);
        setBarWidth("proto-seg-arp", arpPct);
        setBarWidth("proto-seg-dns", dnsPct);
        setBarWidth("proto-seg-other", otherPct);

        safeSetText("pct-tcp", `${tcpPct}%`);
        safeSetText("pct-udp", `${udpPct}%`);
        safeSetText("pct-icmp", `${icmpPct}%`);
        safeSetText("pct-arp", `${arpPct}%`);
        safeSetText("pct-dns", `${dnsPct}%`);
        safeSetText("pct-other", `${otherPct}%`);

        safeSetText("proto-total-tag", `${total.toLocaleString()} packets analyzed`);
    }

    function setBarWidth(id, pct) {
        const el = $(id);
        if (el) {
            el.style.width = `${pct}%`;
            el.title = `${el.id.replace('proto-seg-', '').toUpperCase()}: ${pct}%`;
        }
    }

    // ── Table Rendering: Overview Recent Activity (Section 4) ────────────────
    function addAlertToOverviewTable(alert) {
        const tbody = $("events-tbody");
        if (!tbody) return;

        const emptyRow = tbody.querySelector(".empty-row");
        if (emptyRow) emptyRow.remove();

        const tr = document.createElement("tr");
        tr.className = "clickable";
        tr.onclick = () => openInvestigationModal(alert);

        const timeStr = alert.time || "—";
        const categoryStr = alert.soc_category || "Security Alert";
        const ruleTitle = alert.rule_title || "Unknown Detection";
        const ipStr = alert.ip || "N/A";
        const levelStr = alert.level || "Low";
        const statusStr = alert.status || "Active";

        tr.innerHTML = `
            <td class="mono">${escapeHtml(timeStr)}</td>
            <td><span class="badge badge-neutral">${escapeHtml(categoryStr)}</span></td>
            <td><strong>${escapeHtml(ruleTitle)}</strong></td>
            <td class="mono color-primary">${escapeHtml(ipStr)}</td>
            <td><span class="badge ${severityClass(levelStr)}">${escapeHtml(levelStr)}</span></td>
            <td><span class="status-indicator-dot connected"></span> ${escapeHtml(statusStr)}</td>
        `;

        tbody.insertBefore(tr, tbody.firstChild);

        // Keep maximum 20 visible rows for performance
        while (tbody.children.length > 20) {
            tbody.removeChild(tbody.lastChild);
        }
    }

    // ── Table Rendering: Security Alerts Page (Section 5, 7) ─────────────────
    function renderAlertsPageTable() {
        const tbody = $("alerts-full-tbody");
        if (!tbody) return;

        // Apply filters
        let filtered = state.alerts.filter((a) => {
            // Category filter
            if (state.active_cat_filter !== "all") {
                const catLower = (a.soc_category || "").toLowerCase();
                if (state.active_cat_filter === "auth" && !catLower.includes("auth")) return false;
                if (state.active_cat_filter === "network" && !catLower.includes("network")) return false;
                if (state.active_cat_filter === "fim" && !catLower.includes("file integrity")) return false;
                if (state.active_cat_filter === "ti" && !catLower.includes("threat intelligence")) return false;
                if (state.active_cat_filter === "system" && !catLower.includes("system")) return false;
            }

            // Severity filter
            if (state.active_severity_filter !== "all") {
                const l = (a.level || "").toLowerCase();
                const targetL = state.active_severity_filter.toLowerCase();
                if (targetL === "high" && l !== "high" && l !== "very high") return false;
                if (targetL !== "high" && l !== targetL) return false;
            }

            // Collector filter
            if (state.active_collector_filter !== "all") {
                const col = (a.logsource || "").toLowerCase();
                if (col !== state.active_collector_filter.toLowerCase()) return false;
            }

            // Search query filter (IP, username, rule_title)
            if (state.search_query.trim()) {
                const q = state.search_query.toLowerCase().trim();
                const ipMatch = (a.ip || "").toLowerCase().includes(q);
                const userMatch = (a.username || "").toLowerCase().includes(q);
                const titleMatch = (a.rule_title || "").toLowerCase().includes(q);
                const idMatch = (a.id || "").toLowerCase().includes(q);
                if (!ipMatch && !userMatch && !titleMatch && !idMatch) return false;
            }

            return true;
        });

        // Sorting (Section 7)
        filtered.sort((a, b) => {
            if (state.sort_mode === "newest") return 0; // Already unshifted chronologically
            if (state.sort_mode === "oldest") return -1;
            const rank = { Critical: 4, "Very High": 3, High: 2, Medium: 1, Low: 0 };
            const rA = rank[a.level] || 0;
            const rB = rank[b.level] || 0;
            if (state.sort_mode === "severity_desc") return rB - rA;
            if (state.sort_mode === "severity_asc") return rA - rB;
            return 0;
        });

        safeSetText("alerts-filtered-count", `${filtered.length} alert${filtered.length === 1 ? "" : "s"}`);
        tbody.innerHTML = "";

        if (filtered.length === 0) {
            tbody.innerHTML = '<tr class="empty-row"><td colspan="10" class="empty-state">No matching security alerts found.</td></tr>';
            return;
        }

        filtered.forEach((alert) => {
            const tr = document.createElement("tr");
            tr.className = "clickable";
            tr.onclick = () => openInvestigationModal(alert);

            const riskVal = typeof alert.risk_score === "number" ? alert.risk_score.toFixed(1) : safeVal(alert.risk_score, "0");
            const shortId = (alert.id || "alert").slice(-10);

            tr.innerHTML = `
                <td class="mono">${escapeHtml(shortId)}</td>
                <td class="mono">${escapeHtml(alert.time || "—")}</td>
                <td><span class="badge badge-neutral">${escapeHtml(alert.soc_category || "Security Alert")}</span></td>
                <td><strong>${escapeHtml(alert.rule_title || "Unknown Rule")}</strong></td>
                <td class="mono color-primary">${escapeHtml(alert.ip || "N/A")}</td>
                <td><code>${escapeHtml(alert.logsource || "system")}</code></td>
                <td><span class="badge ${severityClass(alert.level)}">${escapeHtml(alert.level || "Low")}</span></td>
                <td class="mono font-bold">${escapeHtml(riskVal)}/100</td>
                <td><code>${escapeHtml(alert.action || "alert_only")}</code></td>
                <td><span class="badge badge-success">Active</span></td>
            `;
            tbody.appendChild(tr);
        });

        // Update category counts
        updateCategoryTabBadges();
    }

    function updateCategoryTabBadges() {
        const counts = { all: state.alerts.length, auth: 0, network: 0, fim: 0, ti: 0, system: 0 };
        state.alerts.forEach((a) => {
            const cat = (a.soc_category || "").toLowerCase();
            if (cat.includes("auth")) counts.auth++;
            else if (cat.includes("network")) counts.network++;
            else if (cat.includes("file integrity")) counts.fim++;
            else if (cat.includes("threat intelligence")) counts.ti++;
            else counts.system++;
        });

        safeSetText("cat-count-all", counts.all.toString());
        safeSetText("cat-count-auth", counts.auth.toString());
        safeSetText("cat-count-network", counts.network.toString());
        safeSetText("cat-count-fim", counts.fim.toString());
        safeSetText("cat-count-ti", counts.ti.toString());
        safeSetText("cat-count-system", counts.system.toString());

        const sidebarBadge = $("sidebar-alert-badge");
        if (sidebarBadge) {
            if (counts.all > 0) {
                sidebarBadge.style.display = "inline-block";
                sidebarBadge.textContent = counts.all > 99 ? "99+" : counts.all.toString();
            } else {
                sidebarBadge.style.display = "none";
            }
        }
    }

    // ── Table Rendering: Network Activity Stream (Section 8) ─────────────────
    function addNetworkRow(event) {
        const tbody = $("network-events-tbody");
        if (!tbody) return;

        const emptyRow = tbody.querySelector(".empty-row");
        if (emptyRow) emptyRow.remove();

        const tr = document.createElement("tr");
        tr.className = "clickable";
        tr.onclick = () => openNetworkPacketModal(event);

        const timeStr = event.time || new Date().toLocaleTimeString();
        const srcIp = event.ip || "N/A";
        const dstIp = event.dst_ip || "N/A";
        const proto = event.resolved_proto || event.protocol || "OTHER";
        const dport = event.dport || event.dst_port || (event.event_type && event.event_type.includes("dns") ? "53" : "—");
        const evType = event.event_type || "packet_event";

        tr.innerHTML = `
            <td class="mono">${escapeHtml(timeStr)}</td>
            <td class="mono color-primary">${escapeHtml(srcIp)}</td>
            <td class="mono">${escapeHtml(dstIp)}</td>
            <td><span class="proto-seg-tag ${proto.toLowerCase()}">${escapeHtml(proto)}</span></td>
            <td class="mono">${escapeHtml(String(dport))}</td>
            <td><code>${escapeHtml(evType)}</code></td>
        `;

        tbody.insertBefore(tr, tbody.firstChild);

        while (tbody.children.length > 40) {
            tbody.removeChild(tbody.lastChild);
        }
    }

    // ── Table Rendering: Threat Intelligence (Section 10) ────────────────────
    function renderThreatIntelTable() {
        const tbody = $("ti-tbody");
        if (!tbody) return;

        const ips = Object.keys(state.ti_cache);
        if (ips.length === 0) {
            tbody.innerHTML = '<tr class="empty-row"><td colspan="9" class="empty-state">No threat intelligence records yet. Alerts with external IPs will be enriched automatically.</td></tr>';
            safeSetText("ti-table-counter", "0 IPs profiled");
            return;
        }

        tbody.innerHTML = "";
        safeSetText("ti-table-counter", `${ips.length} IP${ips.length === 1 ? "" : "s"} profiled`);

        // Check if all feeds are MockProvider to update banner
        let isMock = true;

        ips.forEach((ip) => {
            const ti = state.ti_cache[ip];
            if (ti.feed && ti.feed !== "MockProvider") {
                isMock = false;
            }

            const tr = document.createElement("tr");
            tr.className = "clickable";
            tr.onclick = () => openTIModal(ip, ti);

            const score = ti.malicious_score || 0;
            const scoreBadgeClass = score >= 80 ? "badge-critical" : score >= 50 ? "badge-high" : "badge-medium";
            const botnetHtml = ti.known_botnet ? '<span class="badge badge-critical">YES</span>' : '<span class="badge badge-neutral">NO</span>';
            const countryStr = ti.country || "Unknown";
            const reportsStr = typeof ti.abuse_reports === "number" ? ti.abuse_reports.toLocaleString() : safeVal(ti.abuse_reports, "0");

            tr.innerHTML = `
                <td class="mono font-bold color-primary">${escapeHtml(ip)}</td>
                <td><strong>${escapeHtml(countryStr)}</strong></td>
                <td><span class="badge ${scoreBadgeClass}">${escapeHtml(String(score))}%</span></td>
                <td>${botnetHtml}</td>
                <td class="mono">${escapeHtml(reportsStr)}</td>
                <td>${escapeHtml(ti.isp || "Unknown ISP")}</td>
                <td class="mono">${escapeHtml(ti.asn || "N/A")}</td>
                <td><code>${escapeHtml(ti.feed || "MockProvider")}</code></td>
                <td class="mono">${new Date().toLocaleTimeString()}</td>
            `;

            tbody.appendChild(tr);
        });

        // Provider banner notice update
        const providerName = isMock ? "MockProvider (Demonstration Mode)" : "AbuseIPDB / Live Threat Feeds";
        safeSetText("ti-banner-provider-name", providerName);
    }

    // ── Table Rendering: File Integrity Monitoring (Section 11) ─────────────
    function renderFIMPage() {
        const tbody = $("fim-tbody");
        if (!tbody) return;

        if (state.fim_violations.length === 0) {
            tbody.innerHTML = '<tr class="empty-row"><td colspan="8" class="empty-state">No file integrity violations detected. Monitored filesystem baselines are clean.</td></tr>';
            safeSetText("fim-table-counter", "0 violations");
            return;
        }

        tbody.innerHTML = "";
        safeSetText("fim-table-counter", `${state.fim_violations.length} violation(s)`);

        state.fim_violations.forEach((violation) => {
            const tr = document.createElement("tr");
            tr.className = "clickable";
            tr.onclick = () => openInvestigationModal(violation);

            const timeStr = violation.time || "—";
            const fileStr = violation.file || (violation.event && violation.event.file) || "Unknown File";
            const eventDesc = violation.event_desc || (violation.event && violation.event.event_desc) || "File Modified";
            const ownerStr = violation.owner || (violation.event && violation.event.owner) || "root";
            const permsStr = violation.permissions || (violation.event && violation.event.permissions) || "N/A";
            const prevHash = safeVal(violation.previous_hash || (violation.event && violation.event.previous_hash), "—");
            const currHash = safeVal(violation.current_hash || (violation.event && violation.event.current_hash), "—");

            tr.innerHTML = `
                <td class="mono">${escapeHtml(timeStr)}</td>
                <td><code>${escapeHtml(fileStr)}</code></td>
                <td><strong class="color-critical">${escapeHtml(eventDesc)}</strong></td>
                <td>${escapeHtml(ownerStr)}</td>
                <td class="mono">${escapeHtml(permsStr)}</td>
                <td class="mono font-xs" title="${escapeHtml(prevHash)}">${escapeHtml(prevHash.slice(0, 16))}…</td>
                <td class="mono font-xs" title="${escapeHtml(currHash)}">${escapeHtml(currHash.slice(0, 16))}…</td>
                <td><span class="badge badge-critical">CRITICAL</span></td>
            `;

            tbody.appendChild(tr);
        });
    }

    // ── Table Rendering: Firewall Responses Ledger (Section 12) ─────────────
    function renderFirewallActionsTable() {
        const tbody = $("firewall-actions-tbody");
        if (!tbody) return;

        if (state.firewall_actions.length === 0) {
            tbody.innerHTML = '<tr class="empty-row"><td colspan="6" class="empty-state">No automated firewall actions recorded. Blocks will appear dynamically upon confirmed execution.</td></tr>';
            return;
        }

        tbody.innerHTML = "";
        state.firewall_actions.forEach((act) => {
            const tr = document.createElement("tr");
            const statusClass = act.status === "Block Successful" ? "badge-success" : act.status.includes("Failed") ? "badge-critical" : "badge-warning";

            tr.innerHTML = `
                <td class="mono">${escapeHtml(act.timestamp || "—")}</td>
                <td class="mono font-bold color-critical">${escapeHtml(act.ip || "Unknown")}</td>
                <td><code>${escapeHtml(act.target || "INPUT")}</code></td>
                <td><span class="badge badge-critical">${escapeHtml(act.action || "DROP")}</span></td>
                <td>${escapeHtml(act.duration || "3600s")}</td>
                <td><span class="badge ${statusClass}">${escapeHtml(act.status || "Status Unknown")}</span></td>
            `;
            tbody.appendChild(tr);
        });
    }

    // ── Table Rendering: Detection Rules (Section 9 - READ-ONLY) ─────────────
    function renderRulesPage() {
        const tbody = $("rules-tbody");
        if (!tbody) return;

        const catFilter = $("filter-rule-cat") ? $("filter-rule-cat").value : "all";
        const statusFilter = $("filter-rule-status") ? $("filter-rule-status").value : "all";

        let filtered = state.rules_catalog.filter((r) => {
            if (catFilter !== "all" && r.category !== catFilter) return false;
            if (statusFilter !== "all" && r.status !== statusFilter) return false;
            return true;
        });

        safeSetText("rules-shown-count", `${filtered.length} Capabilities`);
        tbody.innerHTML = "";

        let activeCount = 0;
        let plannedCount = 0;

        state.rules_catalog.forEach((r) => {
            if (r.status === "ACTIVE") activeCount++;
            else plannedCount++;
        });

        safeSetText("rule-count-active", activeCount.toString());
        safeSetText("rule-count-planned", plannedCount.toString());

        filtered.forEach((rule) => {
            const tr = document.createElement("tr");
            tr.className = "clickable";
            tr.onclick = () => openRuleInspectionModal(rule);

            let pillClass = "active";
            if (rule.status === "PARTIALLY IMPLEMENTED") pillClass = "partial";
            else if (rule.status === "PLANNED") pillClass = "planned";
            else if (rule.status === "NOT IMPLEMENTED") pillClass = "not-implemented";

            tr.innerHTML = `
                <td class="mono">${rule.id}</td>
                <td><strong>${escapeHtml(rule.name)}</strong></td>
                <td><span class="badge badge-neutral">${escapeHtml(rule.category)}</span></td>
                <td class="font-xs">${escapeHtml(rule.detection_method)}</td>
                <td><code>${escapeHtml(rule.data_source)}</code></td>
                <td><span class="badge ${severityClass(rule.severity)}">${escapeHtml(rule.severity)}</span></td>
                <td><span class="status-pill ${pillClass}">${escapeHtml(rule.status)}</span></td>
            `;
            tbody.appendChild(tr);
        });
    }

    // ── Table Rendering: Authentication Events ──────────────────────────────
    function addAuthRow(event) {
        const tbody = $("auth-tbody");
        if (!tbody) return;

        const emptyRow = tbody.querySelector(".empty-row");
        if (emptyRow) emptyRow.remove();

        const tr = document.createElement("tr");
        const timeStr = event.time || new Date().toLocaleTimeString();
        const evType = event.event_type === "failed_login" ? "SSH Failed Login" : event.event_type || "auth_event";
        const ipStr = event.ip || "N/A";
        const userStr = event.username || "root";
        const sev = event.event_type === "failed_login" ? "High" : "Low";

        tr.innerHTML = `
            <td class="mono">${escapeHtml(timeStr)}</td>
            <td><strong class="color-high">${escapeHtml(evType)}</strong></td>
            <td class="mono color-primary">${escapeHtml(ipStr)}</td>
            <td><code>${escapeHtml(userStr)}</code></td>
            <td><span class="badge ${severityClass(sev)}">${escapeHtml(sev)}</span></td>
            <td><code>log_only</code></td>
        `;

        tbody.insertBefore(tr, tbody.firstChild);

        while (tbody.children.length > 30) {
            tbody.removeChild(tbody.lastChild);
        }
    }

    // ── Detailed Forensic Investigation Dossier (Section 6) ──────────────────
    function openInvestigationModal(alert) {
        const modal = $("ti-modal");
        const body = $("modal-body");
        if (!modal || !body) return;

        const ti = alert.threat_intel || {};
        const hasTI = Boolean(ti.matched);
        const riskScore = typeof alert.risk_score === "number" ? alert.risk_score.toFixed(1) : safeVal(alert.risk_score, "0");

        // Threat Intelligence Score Circular Ring Component
        const scoreVal = ti.malicious_score || 0;
        const scoreStroke = Math.min(scoreVal, 100);
        const ringColor = scoreVal >= 80 ? "#EF4444" : scoreVal >= 50 ? "#F97316" : "#F59E0B";

        let tiSectionHtml = "";
        if (hasTI) {
            tiSectionHtml = `
                <div class="ti-score-card">
                    <div class="score-ring">
                        <svg viewBox="0 0 36 36" class="circular-chart">
                            <path class="circle-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                            <path class="circle" stroke="${ringColor}" stroke-dasharray="${scoreStroke}, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                            <text x="18" y="20.35" class="percentage">${scoreVal}%</text>
                        </svg>
                    </div>
                    <div>
                        <strong>External IP Reputation Score</strong>
                        <p class="font-xs" style="color:var(--text-dim);">Feed Provider: <code>${escapeHtml(ti.feed || "Threat Intelligence")}</code></p>
                    </div>
                </div>
                <div class="dossier-grid">
                    <div class="dossier-item"><span class="dossier-label">Geographic Country</span><span class="dossier-val font-bold">${escapeHtml(safeVal(ti.country, "Unknown"))}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Known Botnet Host</span><span class="dossier-val ${ti.known_botnet ? "color-critical font-bold" : ""}">${ti.known_botnet ? "YES (Confirmed C2)" : "No"}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Public Abuse Reports</span><span class="dossier-val">${typeof ti.abuse_reports === "number" ? ti.abuse_reports.toLocaleString() : safeVal(ti.abuse_reports, "0")} reports</span></div>
                    <div class="dossier-item"><span class="dossier-label">ISP & ASN</span><span class="dossier-val">${escapeHtml(safeVal(ti.isp, "Unknown"))} (${escapeHtml(safeVal(ti.asn, "Unknown ASN"))})</span></div>
                </div>
            `;
        } else {
            tiSectionHtml = '<p class="info-text">No threat intelligence data matched for this address or IP is local/internal.</p>';
        }

        // Response confirmation status (Section 6 & 12: Do not claim blocked unless confirmed)
        const isActuallyBlocked = state.blocked_ips.includes(alert.ip);
        const firewallStatusText = isActuallyBlocked ? "Confirmed Blocked (iptables DROP active)" : alert.action === "block_ip" ? "Block Action Dispatched / Logged" : "No Automated Block Configured (alert_only)";
        const firewallBadgeClass = isActuallyBlocked ? "color-critical font-bold" : "color-muted";

        // Build Complete Forensic Dossier HTML safely
        body.innerHTML = `
            <!-- 1. Alert Information -->
            <div class="dossier-section">
                <div class="dossier-sec-title"><span>1. ALERT IDENTIFICATION</span><span class="badge ${severityClass(alert.level)}">${escapeHtml(alert.level || "Low")}</span></div>
                <div class="dossier-grid">
                    <div class="dossier-item"><span class="dossier-label">Alert ID</span><span class="dossier-val mono">${escapeHtml(safeVal(alert.id))}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Detection Rule</span><span class="dossier-val">${escapeHtml(safeVal(alert.rule_title))}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Attack Category</span><span class="dossier-val">${escapeHtml(safeVal(alert.soc_category))}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Detection Timestamp</span><span class="dossier-val mono">${escapeHtml(safeVal(alert.time))}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Source Collector</span><span class="dossier-val mono">${escapeHtml(safeVal(alert.logsource))}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Aggregated Risk Score</span><span class="dossier-val mono font-bold">${escapeHtml(riskScore)} / 100</span></div>
                </div>
            </div>

            <!-- 2. Network Information -->
            <div class="dossier-section">
                <div class="dossier-sec-title"><span>2. NETWORK PARAMETERS</span></div>
                <div class="dossier-grid">
                    <div class="dossier-item"><span class="dossier-label">Source IP</span><span class="dossier-val mono color-primary font-bold">${escapeHtml(safeVal(alert.ip))}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Destination IP</span><span class="dossier-val mono">${escapeHtml(safeVal(alert.dst_ip))}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Source Port</span><span class="dossier-val mono">${escapeHtml(safeVal(alert.sport))}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Destination Port</span><span class="dossier-val mono">${escapeHtml(safeVal(alert.dport))}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Observed Protocol</span><span class="dossier-val mono">${escapeHtml(safeVal(alert.protocol))}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Network Flags</span><span class="dossier-val mono">${escapeHtml(safeVal(alert.flags))}</span></div>
                </div>
            </div>

            <!-- 3. Authentication & Host Context -->
            <div class="dossier-section">
                <div class="dossier-sec-title"><span>3. AUTHENTICATION & TARGET DETAILS</span></div>
                <div class="dossier-grid">
                    <div class="dossier-item"><span class="dossier-label">Target Username</span><span class="dossier-val mono">${escapeHtml(safeVal(alert.username))}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Monitored Service</span><span class="dossier-val">${alert.logsource === "auth" ? "OpenSSH Daemon (sshd)" : alert.logsource === "snort" ? "Snort NIDS" : alert.logsource === "fim" ? "FIM Sentinel" : "Network Sniffer"}</span></div>
                    ${alert.file ? `<div class="dossier-item full-width"><span class="dossier-label">FIM File Path</span><span class="dossier-val mono">${escapeHtml(alert.file)} (${escapeHtml(safeVal(alert.event_desc))})</span></div>` : ""}
                    ${alert.previous_hash ? `<div class="dossier-item full-width"><span class="dossier-label">Previous SHA-256</span><span class="dossier-val mono font-xs">${escapeHtml(alert.previous_hash)}</span></div>` : ""}
                    ${alert.current_hash ? `<div class="dossier-item full-width"><span class="dossier-label">Current SHA-256</span><span class="dossier-val mono font-xs">${escapeHtml(alert.current_hash)}</span></div>` : ""}
                </div>
            </div>

            <!-- 4. Threat Intelligence Dossier -->
            <div class="dossier-section">
                <div class="dossier-sec-title"><span>4. EXTERNAL THREAT INTELLIGENCE</span></div>
                ${tiSectionHtml}
            </div>

            <!-- 5. Automated SOAR Response Information -->
            <div class="dossier-section">
                <div class="dossier-sec-title"><span>5. AUTOMATED RESPONSE STATUS</span></div>
                <div class="dossier-grid">
                    <div class="dossier-item full-width"><span class="dossier-label">Firewall Response State</span><span class="dossier-val ${firewallBadgeClass}">${escapeHtml(firewallStatusText)}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Configured Rule Action</span><span class="dossier-val mono">${escapeHtml(safeVal(alert.action))}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Default Block Duration</span><span class="dossier-val">3600s (Temporary Drop)</span></div>
                    <div class="dossier-item full-width"><span class="dossier-label">Email Notification</span><span class="dossier-val">${alert.level === "Critical" || alert.level === "High" ? "Notification Triggered (Subject to 300s cooldown rate-limit)" : "Suppressed (Threshold below High severity)"}</span></div>
                </div>
            </div>

            <!-- 6. Forensic Technical Evidence & Raw Log -->
            <div class="dossier-section">
                <div class="dossier-sec-title"><span>6. TECHNICAL EVIDENCE & RAW LOG PAYLOAD</span></div>
                <div class="evidence-box">${escapeHtml(safeVal(alert.raw_log, "No raw log string attached to event record."))}</div>
            </div>
        `;

        modal.classList.add("active");
    }

    // ── Network Packet Detail Modal ──────────────────────────────────────────
    function openNetworkPacketModal(event) {
        const modal = $("ti-modal");
        const body = $("modal-body");
        if (!modal || !body) return;

        body.innerHTML = `
            <div class="dossier-section">
                <div class="dossier-sec-title"><span>NETWORK PACKET FORENSICS</span><span class="badge badge-info">${escapeHtml(event.resolved_proto || "PACKET")}</span></div>
                <div class="dossier-grid">
                    <div class="dossier-item"><span class="dossier-label">Timestamp</span><span class="dossier-val mono">${escapeHtml(safeVal(event.time))}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Event Type</span><span class="dossier-val mono">${escapeHtml(safeVal(event.event_type))}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Source IP</span><span class="dossier-val mono color-primary font-bold">${escapeHtml(safeVal(event.ip))}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Destination IP</span><span class="dossier-val mono">${escapeHtml(safeVal(event.dst_ip))}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Source Port</span><span class="dossier-val mono">${escapeHtml(safeVal(event.sport))}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Destination Port</span><span class="dossier-val mono">${escapeHtml(safeVal(event.dport || event.dst_port))}</span></div>
                    <div class="dossier-item full-width"><span class="dossier-label">TCP Flags / Attributes</span><span class="dossier-val mono">${escapeHtml(safeVal(event.flags))}</span></div>
                    ${event.query ? `<div class="dossier-item full-width"><span class="dossier-label">DNS Query String</span><span class="dossier-val mono">${escapeHtml(event.query)}</span></div>` : ""}
                    ${event.entropy ? `<div class="dossier-item"><span class="dossier-label">Shannon Entropy</span><span class="dossier-val mono">${escapeHtml(String(event.entropy))}</span></div>` : ""}
                    ${event.interval ? `<div class="dossier-item"><span class="dossier-label">Beacon Interval</span><span class="dossier-val mono">${escapeHtml(String(event.interval))}s</span></div>` : ""}
                </div>
            </div>
            <div class="dossier-section">
                <div class="dossier-sec-title"><span>RAW LOG & INGESTION TELEMETRY</span></div>
                <div class="evidence-box">${escapeHtml(safeVal(event.raw_log, `Normalized network telemetry packet: ${event.ip} -> ${event.dst_ip || 'host'}`))}</div>
            </div>
        `;

        modal.classList.add("active");
    }

    // ── Rule Inspection Modal (Section 9) ────────────────────────────────────
    function openRuleInspectionModal(rule) {
        const modal = $("ti-modal");
        const body = $("modal-body");
        if (!modal || !body) return;

        body.innerHTML = `
            <div class="dossier-section">
                <div class="dossier-sec-title"><span>SECURITY RULE DEFINITION</span><span class="status-pill ${rule.status === 'ACTIVE' ? 'active' : rule.status === 'PARTIALLY IMPLEMENTED' ? 'partial' : 'planned'}">${escapeHtml(rule.status)}</span></div>
                <div class="dossier-grid">
                    <div class="dossier-item full-width"><span class="dossier-label">Rule / Capability Name</span><span class="dossier-val font-bold" style="font-size:0.95rem;">${escapeHtml(rule.name)}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Security Domain</span><span class="dossier-val">${escapeHtml(rule.category)}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Configured Severity</span><span class="dossier-val badge ${severityClass(rule.severity)}">${escapeHtml(rule.severity)}</span></div>
                    <div class="dossier-item full-width"><span class="dossier-label">Detection Methodology</span><span class="dossier-val">${escapeHtml(rule.detection_method)}</span></div>
                    <div class="dossier-item full-width"><span class="dossier-label">Primary Data Source</span><span class="dossier-val mono">${escapeHtml(rule.data_source)}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Configured Threshold</span><span class="dossier-val mono">${escapeHtml(rule.threshold)}</span></div>
                    <div class="dossier-item"><span class="dossier-label">Evaluation Window</span><span class="dossier-val mono">${escapeHtml(rule.time_window)}</span></div>
                    <div class="dossier-item full-width"><span class="dossier-label">Expected SOAR Response</span><span class="dossier-val mono">${escapeHtml(rule.expected_response)}</span></div>
                    <div class="dossier-item full-width"><span class="dossier-label">Runtime Verification Status</span><span class="dossier-val mono font-bold">${escapeHtml(rule.runtime_status)}</span></div>
                </div>
            </div>

            <div class="dossier-section">
                <div class="dossier-sec-title"><span>CAPABILITY DESCRIPTION & POLICY PURPOSE</span></div>
                <p style="font-size:0.82rem; color:var(--text-main); line-height:1.6;">${escapeHtml(rule.description)}</p>
            </div>
        `;

        modal.classList.add("active");
    }

    // ── Threat Intel Dossier Modal from TI Table ─────────────────────────────
    function openTIModal(ip, ti) {
        openInvestigationModal({
            id: `TI-${ip}`,
            rule_title: `Threat Intelligence Dossier: ${ip}`,
            level: ti.malicious_score >= 80 ? "Critical" : ti.malicious_score >= 50 ? "High" : "Medium",
            ip: ip,
            logsource: "threat_intel",
            risk_score: ti.malicious_score,
            threat_intel: ti,
            time: new Date().toLocaleTimeString(),
            raw_log: `Threat Intelligence enrichment record for IP ${ip} (Origin: ${ti.country || 'Unknown'}, ISP: ${ti.isp || 'Unknown'}, Malicious Score: ${ti.malicious_score || 0}%)`
        });
    }

    window.closeModal = function () {
        const modal = $("ti-modal");
        if (modal) modal.classList.remove("active");
    };

    // ── Render System Status Page (Section 15) ───────────────────────────────
    function renderSystemStatus(data) {
        if (!data || !data.dependencies) return;
        const deps = data.dependencies;

        safeSetText("sys-py-ver", deps.python_version || "3.12+");
        safeSetText("sys-server-time", data.server_time || new Date().toLocaleString());

        const modules = deps.modules || {};
        safeSetModuleStatus("sys-mod-fastapi", modules["FastAPI"]);
        safeSetModuleStatus("sys-mod-uvicorn", modules["Uvicorn"]);
        safeSetModuleStatus("sys-mod-websockets", modules["WebSockets"]);
        safeSetModuleStatus("sys-mod-yaml", modules["PyYAML"]);
        safeSetModuleStatus("sys-mod-scapy", modules["Scapy"]);

        const libpcapEl = $("sys-libpcap-status");
        if (libpcapEl) {
            if (deps.libpcap) {
                libpcapEl.textContent = "Installed (Native C driver)";
                libpcapEl.className = "color-success";
            } else {
                libpcapEl.textContent = "Missing / Limited Capture Mode";
                libpcapEl.className = "color-high";
            }
        }

        const rootEl = $("sys-root-status");
        const privLabel = $("firewall-privilege-label");
        if (rootEl) {
            if (deps.is_root) {
                rootEl.textContent = "Root / Administrator (Full Capabilities)";
                rootEl.className = "color-success";
                if (privLabel) {
                    privLabel.textContent = "Root / Elevated (Active)";
                    privLabel.className = "metric-value color-success";
                }
            } else {
                rootEl.textContent = "Non-Root User (Simulated Mitigation Mode)";
                rootEl.className = "color-medium";
                if (privLabel) {
                    privLabel.textContent = "Non-Root (Simulated)";
                    privLabel.className = "metric-value color-medium";
                }
            }
        }

        safeSetText("sys-pcap-capability", deps.is_root && deps.libpcap ? "Full Promiscuous Sniffing" : "Restricted / Log Stream Active");
    }

    function safeSetModuleStatus(id, info) {
        const el = $(id);
        if (!el) return;
        if (info && info.installed) {
            el.textContent = `OK (${info.version || "Installed"})`;
            el.className = "color-success";
        } else {
            el.textContent = "Missing";
            el.className = "color-critical";
        }
    }

    function renderConfigValues(cfg) {
        const el = $("settings-readout");
        if (!el || !cfg) return;

        el.innerHTML = `
<span style="color:#38BDF8;"># Owl Monitor Active Configuration (Sanitized)</span>
<strong>App Name:</strong>              ${escapeHtml(cfg.app_name)}
<strong>Version:</strong>               ${escapeHtml(cfg.app_version)}

<span style="color:#38BDF8;"># File Integrity Monitoring (FIM)</span>
<strong>FIM Enabled:</strong>           ${cfg.fim ? cfg.fim.enabled : false}
<strong>Check Interval:</strong>        ${cfg.fim ? cfg.fim.check_interval : 60} seconds
<strong>Monitored Targets:</strong>
${cfg.fim && cfg.fim.targets ? cfg.fim.targets.map(t => "  - " + escapeHtml(t)).join("\n") : "  None configured"}

<span style="color:#38BDF8;"># Network Monitoring</span>
<strong>Network Sniffing:</strong>       ${cfg.network ? cfg.network.enabled : false}
<strong>Capture Interface:</strong>      ${cfg.network && cfg.network.interface ? escapeHtml(cfg.network.interface) : "Default interface"}

<span style="color:#38BDF8;"># Automated SOAR Response</span>
<strong>Admin Email:</strong>            ${cfg.response ? escapeHtml(cfg.response.admin_email) : "admin@localhost"}
<strong>Firewall Block Time:</strong>    ${cfg.response ? cfg.response.block_time_seconds : 3600} seconds

<span style="color:#38BDF8;"># Threat Intelligence Feeds</span>
<strong>Mock Provider:</strong>          Active (Demonstration feed)
<strong>AbuseIPDB API:</strong>          ${cfg.threat_intel && cfg.threat_intel.abuseipdb && cfg.threat_intel.abuseipdb.configured ? "Configured (Live API Key present)" : "Unconfigured (No API key in settings.yaml)"}
<strong>OTX Feed:</strong>               ${cfg.threat_intel && cfg.threat_intel.otx && cfg.threat_intel.otx.configured ? "Configured" : "Unconfigured"}
<strong>VirusTotal:</strong>             ${cfg.threat_intel && cfg.threat_intel.virustotal && cfg.threat_intel.virustotal.configured ? "Configured" : "Unconfigured"}
        `;
    }

    // ── Helper Utilities ─────────────────────────────────────────────────────
    function safeSetText(id, text) {
        const el = $(id);
        if (el) el.textContent = text;
    }

    function severityClass(level) {
        const l = (level || "low").toLowerCase();
        if (l === "critical") return "badge-critical";
        if (l === "very high" || l === "high") return "badge-high";
        if (l === "medium") return "badge-medium";
        return "badge-low";
    }

    function flashNotification() {
        const btn = $("notification-btn");
        const countEl = $("notif-count");
        if (!countEl || !btn) return;
        const current = parseInt(countEl.textContent || "0", 10);
        countEl.textContent = (current + 1).toString();
        countEl.style.display = "flex";
    }

    // ── Page Navigation ──────────────────────────────────────────────────────
    const pageTitles = {
        dashboard: { title: "Security Overview", subtitle: "Real-time system security posture and threat detection stream" },
        alerts: { title: "Security Alerts & Incident Investigation", subtitle: "Forensic ledger of confirmed threat signatures and anomaly detections" },
        network: { title: "Advanced Network Security Monitoring", subtitle: "Deep packet inspection metrics, protocol distribution, and attack taxonomy" },
        "threat-intel": { title: "Threat Intelligence & Geolocation", subtitle: "Multi-country attacker IP reputation profiles and threat feed scoring" },
        fim: { title: "File Integrity Monitoring (FIM)", subtitle: "Cryptographic baseline tracking for critical system files" },
        auth: { title: "Authentication Security Monitoring", subtitle: "SSH authentication telemetry, failed attempts, and brute-force tracking" },
        rules: { title: "Detection Rules & Capabilities", subtitle: "Strictly read-only inventory of Sigma-style rules and engine capabilities" },
        firewall: { title: "Automated Firewall & Mitigation Responses", subtitle: "Confirmed iptables DROP actions and automated mitigation ledger" },
        system: { title: "System Health & Environmental Verification", subtitle: "Hardware, driver, privilege, and dependency check transparency" },
        settings: { title: "Configuration Parameters", subtitle: "Sanitized configuration inspection from settings.yaml" }
    };

    function navigateTo(pageId) {
        document.querySelectorAll(".page").forEach((p) => p.classList.add("hidden"));
        const target = $("page-" + pageId);
        if (target) target.classList.remove("hidden");

        document.querySelectorAll("nav li").forEach((li) => li.classList.remove("active"));
        const activeLi = document.querySelector(`nav li[data-page="${pageId}"]`);
        if (activeLi) activeLi.classList.add("active");

        const meta = pageTitles[pageId] || { title: "Owl Monitor", subtitle: "SOC Defense Platform" };
        safeSetText("page-title", meta.title);
        safeSetText("page-subtitle", meta.subtitle);
    }

    // ── Initialization & Event Listeners ─────────────────────────────────────
    document.addEventListener("DOMContentLoaded", () => {
        // Navigation clicks
        document.querySelectorAll("nav li[data-page]").forEach((li) => {
            li.addEventListener("click", (e) => {
                e.preventDefault();
                navigateTo(li.dataset.page);
            });
        });

        // Category filter tabs on Alerts page
        document.querySelectorAll(".cat-tab").forEach((btn) => {
            btn.addEventListener("click", (e) => {
                document.querySelectorAll(".cat-tab").forEach((b) => b.classList.remove("active"));
                e.currentTarget.classList.add("active");
                state.active_cat_filter = e.currentTarget.dataset.cat || "all";
                renderAlertsPageTable();
            });
        });

        // Severity filter dropdown
        const sevSelect = $("filter-severity");
        if (sevSelect) {
            sevSelect.addEventListener("change", (e) => {
                state.active_severity_filter = e.target.value;
                renderAlertsPageTable();
            });
        }

        // Collector filter dropdown
        const colSelect = $("filter-collector");
        if (colSelect) {
            colSelect.addEventListener("change", (e) => {
                state.active_collector_filter = e.target.value;
                renderAlertsPageTable();
            });
        }

        // Sort filter dropdown
        const sortSelect = $("sort-alerts");
        if (sortSelect) {
            sortSelect.addEventListener("change", (e) => {
                state.sort_mode = e.target.value;
                renderAlertsPageTable();
            });
        }

        // Search input with debounce
        const searchInput = $("alert-search-input");
        if (searchInput) {
            searchInput.addEventListener("input", (e) => {
                state.search_query = e.target.value;
                renderAlertsPageTable();
            });
        }

        // Reset filters button
        const resetBtn = $("btn-reset-filters");
        if (resetBtn) {
            resetBtn.addEventListener("click", () => {
                state.active_cat_filter = "all";
                state.active_severity_filter = "all";
                state.active_collector_filter = "all";
                state.search_query = "";
                state.sort_mode = "newest";

                document.querySelectorAll(".cat-tab").forEach((b) => b.classList.remove("active"));
                const allTab = document.querySelector('.cat-tab[data-cat="all"]');
                if (allTab) allTab.classList.add("active");

                if ($("filter-severity")) $("filter-severity").value = "all";
                if ($("filter-collector")) $("filter-collector").value = "all";
                if ($("sort-alerts")) $("sort-alerts").value = "newest";
                if ($("alert-search-input")) $("alert-search-input").value = "";

                renderAlertsPageTable();
            });
        }

        // Rules filters
        const ruleCat = $("filter-rule-cat");
        if (ruleCat) ruleCat.addEventListener("change", renderRulesPage);
        const ruleStatus = $("filter-rule-status");
        if (ruleStatus) ruleStatus.addEventListener("change", renderRulesPage);

        // Network protocol mini-filter
        const netProtoSelect = $("filter-net-proto");
        if (netProtoSelect) {
            netProtoSelect.addEventListener("change", (e) => {
                const targetProto = e.target.value;
                const rows = document.querySelectorAll("#network-events-tbody tr");
                rows.forEach((r) => {
                    if (targetProto === "all") {
                        r.style.display = "";
                    } else {
                        const protoCell = r.querySelector(".proto-seg-tag");
                        if (protoCell && protoCell.textContent.toUpperCase() === targetProto) {
                            r.style.display = "";
                        } else {
                            r.style.display = "none";
                        }
                    }
                });
            });
        }

        // Modal overlay close click
        const modal = $("ti-modal");
        if (modal) {
            modal.addEventListener("click", (e) => {
                if (e.target.id === "ti-modal") closeModal();
            });
        }

        // ESC key to close modal
        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape") closeModal();
        });

        // Notifications button
        const notifBtn = $("notification-btn");
        if (notifBtn) {
            notifBtn.addEventListener("click", () => {
                safeSetText("notif-count", "0");
                const countEl = $("notif-count");
                if (countEl) countEl.style.display = "none";
                navigateTo("alerts");
            });
        }

        // Start WebSocket connection
        connectWebSocket();
    });

})();
