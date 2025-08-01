# NoCEG - Steamworks CEG DRM Resolver
[![GitHub All Releases](https://img.shields.io/github/downloads/iArtorias/noceg/total.svg)](https://github.com/iArtorias/noceg/releases)
> Patch Valve's CEG DRM for legally owned games to ensure long-term accessibility and preservation.

> [!IMPORTANT]  
> NoCEG only works with legally owned games. The game executable that Steam downloads only works with your account and system. NoCEG needs that information to work.

> [!CAUTION]
> This should only be used for personal backups. The final executable still has your hardware info, and is illegal to distribute.
---

## Overview

**NoCEG** is a toolkit designed to fully patch out Valve’s **CEG (Custom Executable Generation)** DRM from *legally purchased* Steam games. Its main purpose is **digital preservation** ensuring that games remain playable even after CEG servers are no longer available.

---

## Components

This repository includes **three core tools** required for resolving and patching CEG protection:

### 🔍 `noceg_signatures`
> A command-line tool to scan the executable for CEG related functions and export the required information to `noceg.json`.

### 🧠 `noceg`
> A dynamic library that uses the vectored exception handling to resolve CEG protected functions (both constant and stolen/masked ones) during runtime using the data from the previously generated `noceg.json`.

### 🧰 `noceg_patcher`
> An utility that applies the final patch to a CEG protected executable.

---

## 🛠️ Usage

### **1. Download the latest release**

Get the latest binaries from the [Releases](https://github.com/iArtorias/noceg/releases) page.

---

### **2. Signature extraction**
Run the following command:
```bash
noceg_signatures.exe "Path\To\GameExecutable.exe"
```

Or simply **drag and drop** the executable onto `noceg_signatures.exe`.

> 🔔 **Note**: If the target executable has **ASLR** enabled, the tool will create a new binary named `<original>_noaslr.exe`. Use this in the next steps.

---

### **3. Inject the runtime library**

- Rename the original `steam_api.dll` to `steam_api_org.dll`.
- Copy `steam_api.dll` from the NoCEG package into the game’s directory.
- Place the generated `noceg.json` file into the same folder.

Now, launch the game. A confirmation window should appear:
> ✅ **"Successfully finished the task!"**

### ⚠️ Special case for select games: `ShouldRestart` option

The following games require `ShouldRestart` to be set to `true` in `noceg.json`:

- Homefront  
- The Darkness II  
- Star Trek  
- F.E.A.R. 3  
- Risen 2

To enable this option, replace this:

```json
"ShouldRestart": false
```
with
```json
"ShouldRestart": true
```

---

### **4. Final Patching**

Drag the original executable onto `noceg_patcher.exe`.  
A modified version will be generated with a suffix like `_noceg.exe` or `_noceg.dll`.

---

### **5. Cleanup**

- Delete `NoCEG`’s `steam_api.dll`.
- Rename `steam_api_org.dll` back to `steam_api.dll`.

---

## 🎮 Supported games (tested)

```txt
✔ 007™ Legends
✔ Aliens: Colonial Marines
✔ Aliens vs. Predator™
✔ Bionic Commando
✔ Call of Duty®: Black Ops
✔ Call of Duty®: Modern Warfare 2
✔ Call of Duty®: Modern Warfare 3
✔ Deadpool
✔ DeathSpank
✔ DeathSpank: Thongs Of Virtue
✔ DiRT Showdown
✔ DiRT Showdown Demo
✔ F1 2012™
✔ F1 Race Stars
✔ F.E.A.R. 3
✔ GRID 2
✔ Homefront
✔ Homefront Demo
✔ Just Cause 2
✔ Just Cause 2 Demo
✔ Kane & Lynch 2: Dog Days
✔ Kane & Lynch 2: Dog Days Demo
✔ Lara Croft and the Guardian of Light
✔ Lara Croft and the Guardian of Light Demo
✔ Madballs in...Babo: Invasion
✔ Madballs in...Babo: Invasion Demo
✔ Mafia II
✔ Mafia II Demo
✔ Prototype 2
✔ Risen 2
✔ Risen 2 Demo
✔ Sid Meier's Ace Patrol
✔ Sid Meier's Ace Patrol: Pacific Skies
✔ Sid Meier's Civilization V
✔ Sid Meier's Civilization V Demo
✔ Sniper Elite V2
✔ Sniper Elite Nazi Zombie Army
✔ Sniper Elite Nazi Zombie Army 2
✔ Spec Ops: The Line
✔ The Amazing Spider-Man
✔ The Bureau: XCOM Declassified
✔ The Darkness II
✔ The Darkness II Demo
✔ The Lord of the Rings: War in the North
✔ Viking: Battle for Asgard
✔ Warhammer 40,000: Space Marine
✔ Warhammer 40,000: Space Marine Demo
✔ XCOM: Enemy Unknown
```

---

## 🚫 Unsupported titles

> These are using allocated buffers for CEG protected functions and are **not supported** at this point:

- ❌ F1 2013™ / F1 2014™  
- ❌ Call of Duty®: Black Ops II  
- ❌ Sid Meier's Civilization®: Beyond Earth™  
- ❌ XCOM: Enemy Within  

---

## Compilation & Dependencies

To compile this project from source, use **Visual Studio 2022**.


This project uses the following open-source libraries:

- [`nlohmann/json`](https://github.com/nlohmann/json) – JSON for Modern C++  
- [`mem`](https://github.com/0x1F9F1/mem) – Memory utility helpers  
- [`zydis`](https://github.com/zyantific/zydis) – Disassembler framework  

---

## Why NoCEG?

- Preserve access to the games long after CEG DRM servers shut down.
- Designed exclusively for **legally owned** copies of games.
- Reverse-engineered with care for accuracy and modularity.

--- 

## 📄 License

Check [LICENSE](LICENSE).

--- 

## 💬 Disclaimer

> ⚠️ **This tool is intended solely for educational and preservation purposes.**  
> Please ensure compliance with local laws and terms of service.

---
