# Command Center HUD & Cockpit Guide 🎛️

The **Command Center HUD** transforms `jfp-edge-radar monitor` into a military-grade terminal cockpit powered by **Ratatui** and **Crossterm**.

---

## 🎨 Dual Tactical Ergonomics

### 1. Tactical Teal (Daytime / High-Information)
* **Palette:** Sea-green and turquoise (`#00DFAB`, `#228B64`) on deep graphite (`#101618`).
* **Design Purpose:** Optimized for rapid ocular pattern recognition. The human eye processes teal and green wavelengths with maximum efficiency, reducing visual strain during prolonged monitoring sessions in illuminated rooms.

### 2. Deep Midnight (Stealth / Total Darkness)
* **Palette:** Deep stealth violet (`#967DFA`) and steel slate (`#4B5A8C`) on dark obsidian (`#12101C`).
* **Design Purpose:** Zero harsh blue/white pixels. Designed for darkroom/night shift operations to prevent retina bleaching and obscure the operator's display from bystanders.

Press **`[T]`** at any moment to switch seamlessly between both themes.

---

## 🚨 The Panic Button (`[ESC]`)

In operational security, discretion is paramount. Pressing **`[ESC]`** immediately wipes the cyber-defense HUD and replaces it with a realistic, scrolling Linux kernel compilation log:

```text
make[1]: Entering directory '/usr/src/linux-6.10.4'
  CC      arch/x86/kernel/process_64.o
  CC      arch/x86/kernel/signal.o
  CC      arch/x86/kernel/traps.o
  CC      arch/x86/kernel/entry_64.o
  CC      kernel/sched/core.o
  CC      kernel/sched/fair.o
  CC      mm/page_alloc.o
  LD      vmlinux.o
  BUILD   arch/x86/boot/bzImage
Kernel: arch/x86/boot/bzImage is ready
```

Pressing **`[ESC]`** a second time instantly restores the security dashboard.

---

## 🕹️ Interactive Keyboard Bindings

| Key | Action | Description |
| :---: | :--- | :--- |
| **`T`** | **Theme Toggle** | Cycles between *Tactical Teal* and *Deep Midnight*. |
| **`F`** | **Focus Mode** | Expands the security ledger table to 100% fullscreen height. |
| **`C`** | **Contrast Mode** | Cycles contrast between *Soft*, *Normal*, and *High*. |
| **`1`** | **Toggle Vectors** | Shows or hides the Ingress Attack Vector breakdown. |
| **`2`** | **Toggle Gauges** | Shows or hides the Tarpit and Memory Bounded capacity gauges. |
| **`3`** | **Toggle Ledger** | Shows or hides the real-time event table. |
| **`R`** | **Export Report** | Compiles an immutable SHA-256 audited SOC report to `/tmp/`. |
| **`↑` / `↓`** | **Scroll Ledger** | Navigates through recorded security events. |
| **`ESC`** | **Panic Conceal** | Hides operations behind a fake GCC kernel build. |
| **`Q`** | **Quit Cockpit** | Restores terminal state cleanly and exits. |
