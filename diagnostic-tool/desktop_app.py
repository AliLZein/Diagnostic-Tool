import ctypes
import sys

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if sys.platform == "win32" and not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()

import os
import re
import subprocess
import logging
import time
import socket
import threading
import multiprocessing
import traceback
from datetime import datetime, timedelta
import sqlite3
import webview
from flask import Flask, jsonify, render_template_string, request, Response

if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

LOG_PATH = os.path.join(
    os.path.dirname(sys.executable) if getattr(sys, "frozen", False)
    else os.path.dirname(os.path.abspath(__file__)),
    "diagnostic_toolkit.log",
)
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logging.info("App starting up...")

_original_popen_init = subprocess.Popen.__init__
def _patched_popen_init(self, *args, **kwargs):
    if os.name == "nt":
        kwargs.setdefault("creationflags", subprocess.CREATE_NO_WINDOW)
    _original_popen_init(self, *args, **kwargs)
subprocess.Popen.__init__ = _patched_popen_init

def _log_thread_exception(args):
    logging.error(f"UNCAUGHT exception in thread '{args.thread.name}':")
    logging.error("".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)))

threading.excepthook = _log_thread_exception

if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.append(BASE_DIR)
from storage.db import get_all_findings, DATA_DIR
import analysis.insights as insights

insights.SETTINGS_FILE = os.path.join(BASE_DIR, "data", "settings.json")
if not os.path.exists(insights.SETTINGS_FILE):
    try:
        os.makedirs(os.path.dirname(insights.SETTINGS_FILE), exist_ok=True)
        insights.save_threshold(5)
    except Exception:
        pass

PROTECTED_PORTS = {80, 443, 53, 5000, 135, 445}

# Global scanner control flag
scan_running = threading.Event()
scan_running.set() # Enabled by default on startup

def get_process_for_port(port):
    """Robust Process Attribution Engine."""
    if not port or port == "N/A":
        return "Unknown Process", "N/A"
    try:
        cmd = f"netstat -ano | findstr :{port}"
        output = subprocess.check_output(cmd, shell=True, text=True)
        lines = output.strip().split("\n")
        for line in lines:
            parts = line.split()
            if len(parts) >= 5 and ("LISTENING" in parts or "ESTABLISHED" in parts):
                pid = parts[-1]
                exe_name = "Unknown"
                try:
                    task = subprocess.check_output(f"tasklist /FI \"PID eq {pid}\" /NH", shell=True, text=True)
                    if task and len(task.split()) > 0:
                        exe_name = task.split()[0]
                except Exception:
                    pass
                return exe_name, pid
    except Exception:
        pass
    return "System/Idle", "N/A"

def scan_os_listening_ports():
    """OS-Level Inspection: Queries the Windows network stack via netstat 
    to instantly discover ALL active listening ports (1-65535) with zero lag."""
    open_ports = set()
    try:
        output = subprocess.check_output("netstat -ano", shell=True, text=True)
        for line in output.strip().split("\n"):
            parts = line.strip().split()
            if len(parts) >= 4 and "LISTENING" in parts:
                local_address = parts[1]
                if ":" in local_address:
                    port_str = local_address.rsplit(":", 1)[1]
                    if port_str.isdigit():
                        open_ports.add(int(port_str))
    except Exception:
        pass
    return open_ports

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()

app = Flask(__name__)

PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Diagnostic Toolkit — Forensics & Remediation</title>
<style>
  /* Global Cursor Customization: Hover changes cursor pointer for interactive elements */
  button, select, input[type="submit"], input[type="button"], label, th, .btn-custom, .btn-purge, .btn-remediate, .btn-dismiss {
    cursor: pointer !important;
  }
  input[type="text"], input[type="number"] {
    cursor: text !important;
  }

  body { background-color: #000000; color: #ffffff; font-family: Segoe UI, sans-serif; margin: 20px; }
  h1 { color: #ff4d4d; font-weight: 600; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; }
  th { color: #ff4d4d; text-align: left; padding: 8px; border-bottom: 2px solid #ff4d4d; }
  td { padding: 8px; border-bottom: 1px solid #333333; font-size: 13px; }
  tr:nth-child(even) { background-color: #1a1a1a; }
  tr:nth-child(odd) { background-color: #111111; }
  tr.anomaly-row { background-color: #3b0000 !important; color: #ff9999 !important; }
  tr.anomaly-row td { color: #ff4d4d !important; font-weight: bold; }
  
  #status { color: #888888; font-size: 12px; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; }
  #action-status-banner { background: #112211; border: 1px solid #28a745; color: #5eff81; padding: 4px 10px; border-radius: 4px; font-weight: bold; display: none; }
  
  #controls { display: flex; align-items: center; gap: 16px; margin-bottom: 16px; font-size: 13px; color: #cccccc; flex-wrap: wrap; }
  #controls input, #controls select { background-color: #1a1a1a; border: 1px solid #444444; color: #ffffff; padding: 6px 8px; border-radius: 4px; }
  
  .btn-custom { background-color: #ff4d4d; color: #000000; border: none; padding: 6px 12px; border-radius: 4px; font-weight: 600; text-decoration: none; display: inline-block; text-align: center; }
  
  /* Engine control button states */
  .btn-go { background-color: #1a2e1a; color: #888888; border: 1px solid #333333; transition: all 0.2s ease; }
  .btn-go.active { background-color: #28a745 !important; color: #ffffff !important; border: 1px solid #5eff81 !important; box-shadow: 0 0 8px rgba(40,167,69,0.5); }
  
  .btn-stop { background-color: #2e1a1a; color: #888888; border: 1px solid #333333; transition: all 0.2s ease; }
  .btn-stop.active { background-color: #dc3545 !important; color: #ffffff !important; border: 1px solid #ff7b88 !important; box-shadow: 0 0 8px rgba(220,53,69,0.5); }
  
  .btn-purge { background-color: #333333 !important; color: #ff4d4d !important; border: 1px solid #ff4d4d !important; }
  .btn-remediate { background-color: #ff3333 !important; color: #ffffff !important; padding: 3px 8px !important; font-size: 11px !important; }
  .btn-dismiss { background-color: #444444 !important; color: #ffffff !important; padding: 3px 8px !important; font-size: 11px !important; margin-left: 4px; border: none; border-radius: 4px; cursor: pointer; }

  .dashboard-grid { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 20px; }
  .stats-card { flex: 1; min-width: 280px; background: #1a1a1a; padding: 15px; border-radius: 6px; border: 1px solid #333333; display: flex; flex-direction: column; justify-content: center; }
  .chart-card { flex: 2; min-width: 350px; background: #1a1a1a; padding: 15px; border-radius: 6px; border: 1px solid #333333; height: 180px; }

  .modal { display: none; position: fixed; z-index: 100; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.85); }
  .modal-content { background: #1a1a1a; border: 2px solid #ff4d4d; margin: 15% auto; padding: 20px; width: 480px; border-radius: 8px; }
  .command-box { background: #000; color: #00ff00; font-family: Consolas, monospace; padding: 8px; border-radius: 4px; font-size: 12px; margin-top: 8px; border: 1px solid #333; word-break: break-all; }
</style>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
</head>
<body>
  <h1>Diagnostic Findings & Threat Forensics</h1>
  <div id="status">
    <span id="status-text">Loading...</span>
    <span id="action-status-banner">✔ Done</span>
  </div>

  <div id="controls">
    <button class="btn-custom btn-go active" id="btn-go" onclick="controlScan('start')">▶ Go (Running)</button>
    <button class="btn-custom btn-stop" id="btn-stop" onclick="controlScan('stop')">⏹ Stop (Paused)</button>
    
    <span style="border-left: 1px solid #444; height: 20px; margin: 0 5px;"></span>

    <label>Retransmission alert threshold: <input type="number" id="threshold-input" min="1" value="5" style="width:60px;"></label>
    <button class="btn-custom" id="save-btn" onclick="saveThreshold()">Save</button>
    <button class="btn-custom" id="export-btn" onclick="exportCsv()">Export CSV</button>
    
    <span style="border-left: 1px solid #444; height: 20px; margin: 0 5px;"></span>

    <label style="color: #4d4dff; font-weight: bold;">Scan Scope:</label>
    <select id="scan-scope-select" onchange="saveScanScopeSettings()">
      <option value="local">Only My Machine (Local Ports)</option>
      <option value="lan">Entire Network (LAN Subnet)</option>
    </select>
  </div>

  <div id="controls" style="background: #111; padding: 10px; border-radius: 6px; border: 1px solid #222;">
    <span style="color: #ff4d4d; font-weight: bold;">Manual Purge: Delete everything older than</span>
    <input type="number" id="purge-value" min="1" value="7" style="width:50px;">
    <select id="purge-unit">
      <option value="minutes">Minutes</option>
      <option value="hours">Hours</option>
      <option value="days" selected>Days</option>
      <option value="weeks">Weeks</option>
      <option value="months">Months</option>
    </select>
    <button class="btn-purge" onclick="purgeData()">Execute Delete</button>
    
    <span style="border-left: 1px solid #444; height: 20px; margin: 0 5px;"></span>

    <span style="color: #4d4dff; font-weight: bold;">Auto-Purge Background Rule:</span>
    <select id="auto-purge-unit" onchange="saveAutoPurgeSettings()">
      <option value="off">Disabled</option>
      <option value="1hour">Keep last 1 Hour</option>
      <option value="24hours" selected>Keep last 24 Hours</option>
      <option value="7days">Keep last 7 Days</option>
      <option value="30days">Keep last 30 Days</option>
    </select>
  </div>

  <div class="dashboard-grid">
      <div class="stats-card">
          <h3 style="color: #ff4d4d; margin-top: 0; font-size: 15px; margin-bottom: 8px;">Top Flagged Threat</h3>
          <p style="margin: 4px 0; font-size: 13px; color: #ccc;">Target: <span id="top-threat-port" style="font-weight: bold; color: #ffffff;">None Detected</span></p>
          <p style="margin: 4px 0; font-size: 13px; color: #ccc;">Process: <span id="top-threat-process" style="font-weight: bold; color: #ff9999;">N/A</span></p>
          <div style="margin-top: 10px;" id="top-threat-action-container">
              <span style="font-size: 12px; color: #777;">Status: System Clean</span>
          </div>
      </div>
      <div class="chart-card">
          <canvas id="categoryHistogram"></canvas>
      </div>
  </div>

  <div id="controls">
    <input type="text" id="search-input" placeholder="Search (e.g., red ; 11:32 ; add ; - wifi)" oninput="renderFindings()" style="flex: 1; padding: 8px 12px; font-size: 14px;">
  </div>

  <table id="findings-table">
    <thead>
      <tr><th>ID</th><th>Time</th><th>Category</th><th>Severity</th><th>Source / Process (PID)</th><th>Message</th><th>Action</th></tr>
    </thead>
    <tbody id="findings-body"></tbody>
  </table>

  <div id="remediationModal" class="modal">
    <div class="modal-content">
      <h3 style="color:#ff4d4d; margin-top:0;">Confirm Remediation Action</h3>
      <p id="modal-desc" style="font-size:13px; color:#ccc;"></p>
      <p style="font-size:12px; color:#ff9999; margin-bottom:4px;">Commands to be executed:</p>
      <div id="modal-cmd-preview" class="command-box"></div>
      <div style="display:flex; justify-content:flex-end; gap:10px; margin-top:15px;">
        <button onclick="closeModal()" style="background:#444; color:#fff; border:none; padding:6px 12px; border-radius:4px; cursor:pointer;">Cancel</button>
        <button id="modal-proceed-btn" style="background:#ff4d4d; color:#000; border:none; padding:6px 12px; border-radius:4px; font-weight:600; cursor:pointer;">Proceed & Execute</button>
      </div>
    </div>
  </div>

  <script>
    let allFindings = [];
    let dismissedIds = new Set();

    function showActionStatus(message) {
      const banner = document.getElementById("action-status-banner");
      banner.innerText = message;
      banner.style.display = "inline-block";
      setTimeout(() => {
        banner.style.display = "none";
      }, 3000);
    }

    async function loadSettings() {
      try {
        const res = await fetch("/settings");
        const data = await res.json();
        if (data.threshold) document.getElementById("threshold-input").value = data.threshold;
        if (data.scan_scope) document.getElementById("scan-scope-select").value = data.scan_scope;
        if (data.autopurge) document.getElementById("auto-purge-unit").value = data.autopurge;
      } catch (err) {}
    }

    async function controlScan(action) {
      const goBtn = document.getElementById("btn-go");
      const stopBtn = document.getElementById("btn-stop");

      showActionStatus(action === "start" ? "Switching engine: Starting..." : "Switching engine: Stopping...");

      try {
        const res = await fetch(`/api/scanner/${action}`, { method: "POST" });
        const data = await res.json();
        
        if (data.status === "ok") {
          if (action === "start") {
            goBtn.classList.add("active");
            goBtn.innerText = "▶ Go (Running)";
            stopBtn.classList.remove("active");
            stopBtn.innerText = "⏹ Stop (Paused)";
            showActionStatus("✔ Engine Running Done");
          } else {
            stopBtn.classList.add("active");
            stopBtn.innerText = "⏹ Stop (Stopped)";
            goBtn.classList.remove("active");
            goBtn.innerText = "▶ Go (Start Engine)";
            showActionStatus("✔ Engine Paused Done");
          }
        }
      } catch (err) {
        showActionStatus("❌ Action Failed");
      }
    }

    function parseTimeToMinutes(str) {
      const m = str.match(/^(\d{1,2}):(\d{2})(?::\d{2})?\s*(am|pm)?$/i);
      if (!m) return null;
      let h = parseInt(m[1], 10);
      const min = parseInt(m[2], 10);
      const period = m[3] ? m[3].toLowerCase() : null;
      if (period === 'pm' && h < 12) h += 12;
      if (period === 'am' && h === 12) h = 0;
      return h * 60 + min;
    }

    function renderFindings() {
      const rawQuery = document.getElementById("search-input").value.trim();
      const tbody = document.getElementById("findings-body");
      tbody.innerHTML = "";

      const terms = rawQuery ? rawQuery.split(';').map(t => t.trim().toLowerCase()).filter(t => t.length > 0) : [];
      
      let positiveTerms = [];
      let negativeTerms = [];
      
      terms.forEach(term => {
        if (term.startsWith('-')) {
          const negClean = term.substring(1).trim();
          if (negClean.length > 0) negativeTerms.push(negClean);
        } else {
          positiveTerms.push(term);
        }
      });

      const hasAdd = positiveTerms.includes("add");
      const textTerms = positiveTerms.filter(t => t !== "add");
      const filteringRed = textTerms.some(t => t === "red" || t === "anomaly");
      const cleanTerms = textTerms.filter(t => t !== "red" && t !== "anomaly");

      let targetTimeMinutes = null;
      let stringFilters = [];
      cleanTerms.forEach(term => {
        const mins = parseTimeToMinutes(term);
        if (mins !== null) {
          targetTimeMinutes = mins;
        } else {
          stringFilters.push(term);
        }
      });

      let windowStart = null, windowEnd = null;
      if (targetTimeMinutes !== null) {
        if (hasAdd) {
          windowStart = targetTimeMinutes - 30;
          windowEnd = targetTimeMinutes + 30;
        } else {
          windowStart = targetTimeMinutes;
          windowEnd = targetTimeMinutes;
        }
      }

      let matchedItems = [];
      allFindings.forEach(f => {
        const localDate = new Date(f.timestamp);
        const itemMinutes = localDate.getHours() * 60 + localDate.getMinutes();
        const isAnomaly = f.severity.toLowerCase() === "warning" || f.severity.toLowerCase() === "error" || f.severity.toLowerCase() === "critical" || f.is_anomaly;
        const haystack = `${localDate.toLocaleString()} ${f.category} ${f.severity} ${f.source} ${f.process_info || ''} ${f.message}`.toLowerCase();

        // Negative filter check (- term)
        let exclude = false;
        for (let neg of negativeTerms) {
          if (haystack.includes(neg)) {
            exclude = true;
            break;
          }
        }
        if (exclude) return;

        if (windowStart !== null && windowEnd !== null) {
          if (hasAdd) {
            if (itemMinutes < windowStart || itemMinutes > windowEnd) return;
          } else {
            if (itemMinutes !== targetTimeMinutes) return;
          }
        }

        if (filteringRed && !isAnomaly) return;

        for (let term of stringFilters) {
          if (!haystack.includes(term)) return;
        }

        matchedItems.push({ f, localDate, isAnomaly });
      });

      matchedItems.sort((a, b) => {
        const aIsPinned = a.isAnomaly && !dismissedIds.has(a.f.id);
        const bIsPinned = b.isAnomaly && !dismissedIds.has(b.f.id);

        if (aIsPinned && !bIsPinned) return -1;
        if (!aIsPinned && bIsPinned) return 1;

        return b.f.id - a.f.id;
      });

      matchedItems.forEach(({ f, localDate, isAnomaly }) => {
        const row = document.createElement("tr");
        if (isAnomaly) row.className = "anomaly-row";
        
        const procDisplay = (f.process_info && f.process_info !== "N/A") ? `${f.source} -> <strong>${f.process_info}</strong> (PID: ${f.pid})` : f.source;
        
        let actionButtons = `<button class="btn-action btn-remediate" onclick="openRemediationModal('${f.port || ''}', '${f.pid || 'N/A'}')">Mitigate</button>`;
        
        if (isAnomaly && !dismissedIds.has(f.id)) {
          actionButtons += `<button class="btn-dismiss" onclick="dismissAlert(${f.id})">Dismiss</button>`;
        }

        row.innerHTML = `
          <td>${f.id}</td>
          <td>${localDate.toLocaleTimeString()}</td>
          <td>${f.category}</td>
          <td>${f.severity}</td>
          <td>${procDisplay}</td>
          <td>${f.message}</td>
          <td>${actionButtons}</td>
        `;
        tbody.appendChild(row);
      });
    }

    function dismissAlert(id) {
      dismissedIds.add(id);
      renderFindings();
    }

    function openRemediationModal(port, pid) {
      const modal = document.getElementById("remediationModal");
      const desc = document.getElementById("modal-desc");
      const cmdPreview = document.getElementById("modal-cmd-preview");
      const btn = document.getElementById("modal-proceed-btn");

      if (!port) {
        alert("No specific port associated with this finding -- nothing to mitigate.");
        return;
      }

      desc.innerText = `Target port: ${port} | PID: ${pid}\nAction: Terminate PID tree & apply firewall block rule.`;

      let previewText = "";
      if (pid && pid !== "N/A") {
        previewText += `taskkill /F /T /PID ${pid}\n`;
      }
      previewText += `netsh advfirewall firewall add rule name="Toolkit_Block_${port}" dir=in protocol=TCP localport=${port} action=block`;
      cmdPreview.innerText = previewText;

      btn.onclick = function() { executeMitigation(port, pid); };
      modal.style.display = "block";
    }

    function closeModal() {
      document.getElementById("remediationModal").style.display = "none";
    }

    async function executeMitigation(port, pid) {
      closeModal();
      showActionStatus("Executing mitigation...");
      try {
        const res = await fetch("/api/remediate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ port: port, pid: pid })
        });
        const data = await res.json();
        alert(data.message);
        showActionStatus("✔ Mitigation Done");
        refreshData();
      } catch (err) {
        alert("Remediation failed -- check logs.");
        showActionStatus("❌ Mitigation Failed");
      }
    }

    async function refreshData() {
      try {
        const res = await fetch("/data");
        allFindings = await res.json();
        renderFindings();
        document.getElementById("status-text").innerText = "Last updated: " + new Date().toLocaleTimeString();
      } catch (err) {
        document.getElementById("status-text").innerText = "Connection lost -- retrying...";
      }
    }

    let categoryChart = null;
    async function refreshMetrics() {
      try {
        const res = await fetch("/api/metrics");
        const data = await res.json();
        
        if (data.top_threat) {
          document.getElementById("top-threat-port").innerText = `Port ${data.top_threat.port}`;
          document.getElementById("top-threat-process").innerText = `${data.top_threat.process_info} (PID: ${data.top_threat.pid})`;
          document.getElementById("top-threat-action-container").innerHTML = `
            <button class="btn-action btn-remediate" style="font-size: 12px !important; padding: 5px 10px !important;" onclick="openRemediationModal('${data.top_threat.port}', '${data.top_threat.pid}')">Mitigate Top Threat</button>
          `;
        } else {
          document.getElementById("top-threat-port").innerText = "None Detected";
          document.getElementById("top-threat-process").innerText = "N/A";
          document.getElementById("top-threat-action-container").innerHTML = `<span style="font-size: 12px; color: #777;">Status: System Clean</span>`;
        }

        if (!categoryChart) {
          const ctx = document.getElementById("categoryHistogram").getContext("2d");
          categoryChart = new Chart(ctx, {
            type: "bar",
            data: {
              labels: data.categories,
              datasets: [{
                data: data.counts,
                backgroundColor: "rgba(255, 77, 77, 0.6)",
                borderColor: "#ff4d4d",
                borderWidth: 1,
                maxBarThickness: 60
              }]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              interaction: { mode: 'nearest', intersect: false },
              plugins: { 
                legend: { display: false },
                tooltip: { callbacks: { label: function(context) { return context.parsed.y.toLocaleString(); } } }
              },
              scales: {
                x: { ticks: { color: "#888888" }, grid: { color: "#222222" } },
                y: { 
                  ticks: { color: "#888888", callback: function(value) { return value.toLocaleString(); } }, 
                  grid: { color: "#222222" }, 
                  beginAtZero: true 
                }
              }
            }
          });
        } else {
          categoryChart.data.labels = data.categories;
          categoryChart.data.datasets[0].data = data.counts;
          categoryChart.update();
        }
      } catch (err) {}
    }

    async function saveThreshold() {
      const value = document.getElementById("threshold-input").value;
      const saveBtn = document.getElementById("save-btn");
      const originalText = saveBtn.innerText;

      showActionStatus("Saving threshold...");
      try {
        const res = await fetch("/settings", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ threshold: value })
        });
        const data = await res.json();
        if (data.status === "ok") {
          saveBtn.innerText = "✓";
          saveBtn.style.backgroundColor = "#28a745";
          saveBtn.style.color = "#ffffff";
          setTimeout(() => {
            saveBtn.innerText = originalText;
            saveBtn.style.backgroundColor = "#ff4d4d";
            saveBtn.style.color = "#000000";
          }, 2000);
          showActionStatus("✔ Threshold Saved Done");
          refreshMetrics();
          refreshData();
        }
      } catch (err) {
        alert("Failed to save threshold.");
        showActionStatus("❌ Save Failed");
      }
    }

    async function saveScanScopeSettings() {
      const scope = document.getElementById("scan-scope-select").value;
      showActionStatus("Switching scan scope...");
      await fetch("/settings/scanscope", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scan_scope: scope })
      });
      showActionStatus("✔ Scope Switched Done");
    }

    async function exportCsv() {
      const exportBtn = document.getElementById("export-btn");
      const originalText = exportBtn.innerText;

      showActionStatus("Exporting CSV...");
      try {
        const res = await fetch("/export.csv");
        const data = await res.json();
        
        exportBtn.innerText = "✓";
        exportBtn.style.backgroundColor = "#28a745";
        exportBtn.style.color = "#ffffff";
        setTimeout(() => {
          exportBtn.innerText = originalText;
          exportBtn.style.backgroundColor = "#ff4d4d";
          exportBtn.style.color = "#000000";
        }, 2000);

        showActionStatus("✔ Export Done");
        alert(`Exported ${data.count.toLocaleString()} items to:\n${data.path}`);
      } catch (err) {
        alert("Export failed.");
        showActionStatus("❌ Export Failed");
      }
    }

    async function saveAutoPurgeSettings() {
      const setting = document.getElementById("auto-purge-unit").value;
      showActionStatus("Updating auto-purge rule...");
      await fetch("/settings/autopurge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ autopurge: setting })
      });
      showActionStatus("✔ Auto-Purge Rule Saved Done");
    }

    async function purgeData() {
      const val = document.getElementById("purge-value").value;
      const unit = document.getElementById("purge-unit").value;
      if (!confirm(`Delete findings older than ${val} ${unit}?`)) return;
      
      showActionStatus("Executing deletion...");
      const res = await fetch("/api/purge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ value: val, unit: unit })
      });
      const data = await res.json();
      showActionStatus("✔ Deletion Done");
      alert(`Successfully deleted ${data.deleted_count.toLocaleString()} old records.`);
      
      document.getElementById("purge-value").value = "7";
      document.getElementById("purge-unit").value = "days";
      dismissedIds.clear();

      refreshData();
      refreshMetrics();
    }

    loadSettings();
    refreshData();
    refreshMetrics();
    setInterval(refreshData, 1000);
    setInterval(refreshMetrics, 3000);
  </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(PAGE_TEMPLATE)

@app.route("/api/scanner/start", methods=["POST"])
def api_scanner_start():
    scan_running.set()
    logging.info("Diagnostic engine manually resumed via UI.")
    return jsonify({"status": "ok", "message": "Diagnostic engine started."})

@app.route("/api/scanner/stop", methods=["POST"])
def api_scanner_stop():
    scan_running.clear()
    logging.info("Diagnostic engine manually paused via UI.")
    return jsonify({"status": "ok", "message": "Diagnostic engine stopped."})

@app.route("/data")
def data():
    findings = get_all_findings()
    threshold = insights.load_threshold()
    retrans_count = sum(1 for f in findings if "retransmission" in f.message.lower())
    
    enriched = []
    for f in findings:
        is_retrans = "retransmission" in f.message.lower()
        
        if is_retrans:
            is_anomaly = (retrans_count >= threshold)
        else:
            is_anomaly = f.severity.lower() in ("warning", "error", "critical")

        port_match = re.search(r':\s*(\d{2,5})\s*$', f.message)
        port_num = port_match.group(1) if port_match else None
        exe_name, pid = get_process_for_port(port_num) if port_num else ("System/Idle", "N/A")

        severity_str = "warning" if is_anomaly else "info"

        enriched.append({
            "id": f.id,
            "timestamp": f.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "category": f.category,
            "severity": severity_str,
            "source": f.source,
            "message": f.message,
            "is_anomaly": is_anomaly,
            "process_info": exe_name,
            "pid": pid,
            "port": port_num,
        })
    return jsonify(enriched)

@app.route("/api/metrics")
def api_metrics():
    findings = get_all_findings()
    threshold = insights.load_threshold()
    retrans_count = sum(1 for f in findings if "retransmission" in f.message.lower())
    open_ports = sum(1 for f in findings if "open port" in f.message.lower() and "closed" not in f.message.lower())
    closed_ports = sum(1 for f in findings if "closed" in f.message.lower())
    
    retrans_is_anomaly = (retrans_count >= threshold)
    base_anomalies = len([f for f in findings if f.severity.lower() in ("warning", "error", "critical") and "retransmission" not in f.message.lower()])
    total_anomalies = base_anomalies + (1 if retrans_is_anomaly and retrans_count > 0 else 0)
        
    top_threat = None
    for f in reversed(findings):
        is_anomaly = f.severity.lower() in ("warning", "error", "critical") or "retransmission" in f.message.lower()
        if is_anomaly:
            port_match = re.search(r':\s*(\d{2,5})\s*$', f.message)
            port_num = port_match.group(1) if port_match else None
            if port_num:
                exe_name, pid = get_process_for_port(port_num)
                top_threat = {
                    "port": port_num,
                    "process_info": exe_name,
                    "pid": pid,
                    "message": f.message
                }
                break

    return jsonify({
        "total_anomalies": total_anomalies,
        "categories": ["Retransmissions", "Open Ports", "Closed Ports", "Anomalies"],
        "counts": [retrans_count, open_ports, closed_ports, total_anomalies],
        "top_threat": top_threat
    })

@app.route("/api/remediate", methods=["POST"])
def api_remediate():
    """Foolproof Remediation using explicit port and PID parameters."""
    payload = request.get_json(silent=True) or {}
    port_val = str(payload.get("port", "")).strip() or None
    pid = payload.get("pid", "N/A")

    if port_val and port_val.isdigit():
        port_int = int(port_val)
        for protected in PROTECTED_PORTS:
            if port_int == protected:
                return jsonify({"status": "blocked", "message": f"Remediation Refused: Port {protected} is a core system port."}), 400

    actions_taken = []
    try:
        if pid != "N/A" and str(pid).isdigit():
            subprocess.run(f"taskkill /F /T /PID {pid}", shell=True, check=True)
            actions_taken.append(f"Terminated PID tree {pid}")

        if port_val and port_val.isdigit():
            fw_cmd = f"netsh advfirewall firewall add rule name=\"Toolkit_Block_{port_val}\" dir=in protocol=TCP localport={port_val} action=block"
            subprocess.run(fw_cmd, shell=True, check=True)
            actions_taken.append(f"Firewall block applied on port {port_val}")

        if actions_taken:
            return jsonify({"status": "ok", "message": "Mitigation successful: " + " | ".join(actions_taken)})
        else:
            return jsonify({"status": "error", "message": "Could not determine a valid port or PID for this finding."}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"Mitigation failed: {str(e)}"}), 500

def reset_finding_ids(cursor):
    """Renumber all remaining findings from 1 upward chronologically."""
    cursor.execute("SELECT id FROM findings ORDER BY timestamp ASC, id ASC")
    existing_ids = [row[0] for row in cursor.fetchall()]

    if not existing_ids:
        try:
            cursor.execute("DELETE FROM sqlite_sequence WHERE name = 'findings'")
        except sqlite3.OperationalError:
            pass
        return

    cursor.execute("UPDATE findings SET id = -id")

    for new_id, old_id in enumerate(existing_ids, start=1):
        cursor.execute(
            "UPDATE findings SET id = ? WHERE id = ?",
            (new_id, -old_id)
        )

    try:
        cursor.execute(
            "UPDATE sqlite_sequence SET seq = ? WHERE name = 'findings'",
            (len(existing_ids),)
        )
    except sqlite3.OperationalError:
        pass

@app.route("/api/purge", methods=["POST"])
def api_purge():
    payload = request.get_json(silent=True) or {}
    val = int(payload.get("value", 7))
    unit = payload.get("unit", "days")

    now = datetime.utcnow()
    deltas = {
        "minutes": timedelta(minutes=val),
        "hours": timedelta(hours=val),
        "days": timedelta(days=val),
        "weeks": timedelta(weeks=val),
        "months": timedelta(days=val * 30)
    }
    cutoff = now - deltas.get(unit, timedelta(days=val))

    db_path = os.path.join(DATA_DIR, "findings.db")
    deleted_count = 0
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp FROM findings")
        rows = cursor.fetchall()
        
        ids_to_delete = []
        for row_id, ts_str in rows:
            try:
                cleaned_ts = ts_str.replace("Z", "").split(".")[0]
                dt = datetime.fromisoformat(cleaned_ts)
                if dt < cutoff:
                    ids_to_delete.append(row_id)
            except Exception:
                pass

        if ids_to_delete:
            cursor.executemany("DELETE FROM findings WHERE id = ?", [(i,) for i in ids_to_delete])
            deleted_count = len(ids_to_delete)

            reset_finding_ids(cursor)
            conn.commit()
        conn.close()

    return jsonify({"status": "ok", "deleted_count": deleted_count})

@app.route("/settings", methods=["GET", "POST"])
def settings():
    import json
    settings_path = insights.SETTINGS_FILE
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        if "threshold" in payload:
            insights.save_threshold(int(payload.get("threshold", 5)))
        return jsonify({"status": "ok"})
    
    thresh = insights.load_threshold()
    scope = "local"
    autopurge = "24hours"
    try:
        if os.path.exists(settings_path):
            with open(settings_path, "r") as f:
                sdata = json.load(f)
                scope = sdata.get("scan_scope", "local")
                autopurge = sdata.get("autopurge", "24hours")
    except Exception:
        pass
    return jsonify({"threshold": thresh, "scan_scope": scope, "autopurge": autopurge})

@app.route("/settings/scanscope", methods=["POST"])
def settings_scanscope():
    payload = request.get_json(silent=True) or {}
    scope = payload.get("scan_scope", "local")
    import json
    settings_path = insights.SETTINGS_FILE
    try:
        with open(settings_path, "r") as f:
            data = json.load(f)
    except Exception:
        data = {}
    data["scan_scope"] = scope
    with open(settings_path, "w") as f:
        json.dump(data, f, indent=4)
    return jsonify({"status": "ok"})

@app.route("/settings/autopurge", methods=["POST"])
def settings_autopurge():
    payload = request.get_json(silent=True) or {}
    setting = payload.get("autopurge", "24hours")
    import json
    settings_path = insights.SETTINGS_FILE
    try:
        with open(settings_path, "r") as f:
            data = json.load(f)
    except Exception:
        data = {}
    data["autopurge"] = setting
    with open(settings_path, "w") as f:
        json.dump(data, f, indent=4)
    return jsonify({"status": "ok"})

@app.route("/export.csv")
def export_csv():
    import csv
    findings = get_all_findings()
    export_path = os.path.join(DATA_DIR, "findings_export.csv")
    with open(export_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "Timestamp", "Category", "Severity", "Source", "Message"])
        for finding in findings:
            writer.writerow([finding.id, finding.timestamp.isoformat(), finding.category, finding.severity, finding.source, finding.message])
    return jsonify({"status": "ok", "path": export_path, "count": len(findings)})

def background_diagnostic_loop(interval_seconds=0.5):
    local_ip = get_local_ip()
    cycle_counter = 0
    lan_scan_counter = 0
    while True:
        if not scan_running.is_set():
            time.sleep(0.5)
            continue

        try:
            from packet_analyzer.custom_sniffer import sniff_traffic
            from network_scanner.lan_scanner import scan_lan
            import json

            scan_scope = "local"
            try:
                if os.path.exists(insights.SETTINGS_FILE):
                    with open(insights.SETTINGS_FILE, "r") as sf:
                        sdata = json.load(sf)
                        scan_scope = sdata.get("scan_scope", "local")
            except Exception:
                pass

            db_path = os.path.join(DATA_DIR, "findings.db")

            active_ports = scan_os_listening_ports()
            for port in active_ports:
                if port not in PROTECTED_PORTS and port != 5000:
                    if os.path.exists(db_path):
                        conn = sqlite3.connect(db_path)
                        cursor = conn.cursor()
                        cursor.execute(
                            "SELECT id FROM findings WHERE source = ? AND timestamp >= datetime('now', '-30 seconds')",
                            (f"Port {port}",)
                        )
                        existing = cursor.fetchone()
                        if not existing:
                            cursor.execute(
                                "INSERT INTO findings (timestamp, category, severity, source, message) VALUES (?, ?, ?, ?, ?)",
                                (datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), "security", "warning", f"Port {port}", f"New open port detected: {port}")
                            )
                            conn.commit()
                        conn.close()

            if scan_scope == "lan":
                lan_scan_counter += 1
                if lan_scan_counter >= 30:
                    lan_scan_counter = 0
                    try:
                        lan_results = scan_lan(local_ip)
                        for host, host_findings in lan_results.items():
                            for finding in host_findings:
                                msg = str(finding)
                                if os.path.exists(db_path):
                                    conn = sqlite3.connect(db_path)
                                    cursor = conn.cursor()
                                    cursor.execute(
                                        "SELECT id FROM findings WHERE source = ? AND message = ? AND timestamp >= datetime('now', '-120 seconds')",
                                        (f"LAN {host}", msg)
                                    )
                                    if not cursor.fetchone():
                                        cursor.execute(
                                            "INSERT INTO findings (timestamp, category, severity, source, message) VALUES (?, ?, ?, ?, ?)",
                                            (datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), "network", "warning", f"LAN {host}", msg)
                                        )
                                        conn.commit()
                                    conn.close()
                    except Exception:
                        pass

            sniff_traffic(local_ip=local_ip, duration=5)

            cycle_counter += 1
            if cycle_counter >= 60:
                cycle_counter = 0
                try:
                    with open(insights.SETTINGS_FILE, "r") as sf:
                        sdata = json.load(sf)
                    ap_setting = sdata.get("autopurge", "24hours")
                    if ap_setting != "off":
                        hours_map = {"1hour": 1, "24hours": 24, "7days": 24*7, "30days": 24*30}
                        hrs = hours_map.get(ap_setting, 24)
                        cutoff_auto = datetime.utcnow() - timedelta(hours=hrs)
                        
                        db_p = os.path.join(DATA_DIR, "findings.db")
                        if os.path.exists(db_p):
                            conn = sqlite3.connect(db_p)
                            cur = conn.cursor()
                            cur.execute("SELECT id, timestamp FROM findings")
                            rows = cur.fetchall()
                            auto_del_ids = []
                            for rid, tstr in rows:
                                try:
                                    dt_clean = tstr.replace("Z", "").split(".")[0]
                                    if datetime.fromisoformat(dt_clean) < cutoff_auto:
                                        auto_del_ids.append(rid)
                                except Exception:
                                    pass
                            if auto_del_ids:
                                cur.executemany("DELETE FROM findings WHERE id = ?", [(i,) for i in auto_del_ids])
                                reset_finding_ids(cur)
                                conn.commit()
                            conn.close()
                except Exception:
                    pass
        except Exception:
            logging.exception("Background loop error")
        time.sleep(interval_seconds)
        
def wait_for_server(host, port, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=0.5): return True
        except OSError: time.sleep(0.2)
    return False

def run_flask():
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)

def on_closed():
    os._exit(0)

def main():
    flask_thread = threading.Thread(target=run_flask, daemon=True, name="FlaskThread")
    flask_thread.start()
    if not wait_for_server("127.0.0.1", 5000): sys.exit(1)

    diag_thread = threading.Thread(target=background_diagnostic_loop, args=(0.5,), daemon=True, name="DiagnosticThread")
    diag_thread.start()

    window = webview.create_window("Diagnostic Toolkit", "http://127.0.0.1:5000", width=1050, height=720, resizable=True)
    window.events.closed += on_closed
    webview.start()

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()