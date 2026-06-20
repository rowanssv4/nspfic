# NSPFIC — Network Space Proxy Fingerprint Intelligence Collector

[![Automated Workflow](https://github.com/rowanssv4/nspfic/actions/workflows/auto-update.yml/badge.svg)](https://github.com/rowanssv4/nspfic/actions)
[![Security Compliance](https://img.shields.io/badge/Security-Strict_Compliance-green.svg)](https://github.com/rowanssv4)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[<img src="https://cdnjs.cloudflare.com/ajax/libs/flag-icon-css/3.4.6/flags/4x3/us.svg" width="20"/> English Description](#english-version) | [<img src="https://cdnjs.cloudflare.com/ajax/libs/flag-icon-css/3.4.6/flags/4x3/tw.svg" width="20"/> 中文版本](#中文版本)

---

## English Version

### What is NSPFIC?

NSPFIC is a fully automated pipeline that collects public proxy fingerprints scattered across open-source intelligence feeds, cleanses the data, performs ASN (Autonomous System Number) lookups, and outputs structured, labeled datasets (`nodes.txt` / `sub.txt`) — updated on a schedule via GitHub Actions.

### Features

- ⚡ **Fast** — each run completes in under 25 seconds
- 🔒 **Rate-limited** — capped at 120 API calls per run to prevent abuse
- 🧠 **Dual-engine fingerprinting** — online API for top-priority nodes; regex matrix fallback for the rest
- 🛡️ **AST-level sanitization** — strips malicious redirects and config exploits before persisting data
- 🌍 **ASN enrichment** — tags each proxy with carrier type (`Residential`, `Datacenter`, backbone)

### Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/rowanssv4/nspfic.git
cd nspfic

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the scraper
python scraper.py
```

Output files:
- `nodes.txt` — plain-text proxy list with fingerprint labels
- `sub.txt` — subscription-format output
- `report.txt` — run summary and stats

### How It Works

```
Open-source feeds
      │
      ▼
  Fetching & Deduplication
      │
      ▼
  Dual-engine ASN Lookup
  ├── Top 120 nodes → Online API (precise carrier metadata)
  └── Remaining nodes → Offline regex matrix (fast classification)
      │
      ▼
  AST Sanitization (strip malicious payloads)
      │
      ▼
  Structured Output (nodes.txt / sub.txt)
```

### Design Decisions

**Why no active ping/connection testing?**
Mass TCP handshakes or ICMP probes in a CI environment cause I/O queue stalls and risk triggering ISP anti-scan blacklists. All connection verification is offloaded to the client side.

**Why GitHub Actions?**
GitHub's tier-1 BGP network edges provide reliable, globally distributed fetch performance. Git's version control replaces the need for a dedicated database — state diffs are committed by a headless bot.

**Why the 120-request cap?**
Strictly to avoid hitting third-party API rate limits (HTTP 429) and to ensure this project never abuses GitHub's free compute quota.

### ⚠️ Legal Disclaimer

This project is an open-source technical artifact for **academic research, protocol analysis, and DevOps automation practice only**.

Users are solely responsible for complying with all applicable laws and regulations in their jurisdiction. The developer assumes **no liability** for any misuse of the generated datasets, network penetration activities, or legal violations arising from use of this project. **Use at your own risk.**

This repository operates in strict compliance with [GitHub's Terms of Service](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service).

---

## 中文版本

### 這是什麼？

NSPFIC 是一個全自動的代理指紋情報收集流水線。它從公開的開源情報源中採集散落的代理節點，進行清洗、去重、ASN 歸屬反查，最終輸出帶有載體標籤的結構化資料集（`nodes.txt` / `sub.txt`），並透過 GitHub Actions 定時自動更新。

### 功能特色

- ⚡ **高速** — 單次全流程執行嚴格控制在 25 秒以內
- 🔒 **防濫用熔斷** — 線上 API 查詢硬性上限 120 次/次，杜絕資源濫用
- 🧠 **雙引擎混合指紋** — 高優先節點走線上 API 精查，後備節點走本地正則矩陣秒級分類
- 🛡️ **AST 安全前置過濾** — 序列化前攔截並剔除惡意 HTML 導向與異常設定偽裝
- 🌍 **ASN 情報富化** — 為每個代理標記載體類型（住宅 / 機房 / 主干網骨幹）

### 快速開始

```bash
# 1. 克隆倉庫
git clone https://github.com/rowanssv4/nspfic.git
cd nspfic

# 2. 安裝依賴
pip install -r requirements.txt

# 3. 執行採集
python scraper.py
```

輸出文件說明：
- `nodes.txt` — 帶指紋標籤的明文代理列表
- `sub.txt` — 訂閱格式輸出
- `report.txt` — 本次執行摘要與統計

### 運作流程

```
開源情報源
    │
    ▼
  採集 & 去重
    │
    ▼
  雙引擎 ASN 反查
  ├── 前 120 個核心節點 → 線上 API 精查（真實載體資訊）
  └── 其餘節點 → 本地輕量 Regex 矩陣（秒級分類）
    │
    ▼
  AST 安全過濾（攔截惡意載荷）
    │
    ▼
  結構化輸出（nodes.txt / sub.txt）
```

### 設計決策

**為什麼不做主動連通性測試（No-Ping 策略）？**
在 CI/CD 虛擬環境中執行海量 TCP 握手或 ICMP 探測，極易因死節點逾時堆積造成 I/O 隊列卡死，甚至被電信商防禦系統誤判為異常掃描而封鎖 IP。因此本專案將連通性驗證完全交由用戶端在地非同步執行，核心流程僅負責採集與清洗。

**為什麼選擇 GitHub Actions？**
GitHub 的全球頂級 BGP 互聯網路邊緣，確保了拉取分布在不同國家開源資源時的傳輸效率。Git 版本拓撲特性替代了獨立資料庫的需求——執行狀態增量覆蓋透過 Headless Bot 的 force push 無縫完成，大幅降低維運成本。

**為什麼限制 120 次 API 請求？**
為了嚴格規避第三方 API 頻率限制（HTTP 429 Too Many Requests），同時確保本專案在任何情況下都不濫用 GitHub Actions 的免費運算資源配額。

### ⚠️ 法律免責聲明

本專案屬純粹的**開源技術研究產物**，僅供學術研究、網路協定分析及自動化運維（DevOps）技術練習使用。

使用者在使用本專案或衍生資料時，**必須嚴格遵守所在國家或地區的在地法律法規**。任何因不當操作、違規使用或非法網路穿透行為所引發的法律訴訟、行政制裁或系統性風險，均由使用者本人承擔全部責任。專案開發者對此概不負責，亦不承擔任何直接、間接或連帶之法律責任。**風險自擔。**

本專案嚴格遵循 [GitHub 服務條款（TOS）](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service) 執行。

---

<div align="center">
  <sub>Made with ❤️ for the open-source community · 僅供學術研究使用</sub>
</div>
