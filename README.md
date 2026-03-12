# 🌲 IDA Pro Call Tree Analysis Plugin

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![IDA Version](https://img.shields.io/badge/IDA-7.0%2B-blue.svg)](https://hex-rays.com/ida-pro/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-green.svg)](https://www.python.org/)

IDA Pro plugin for recursive function call tree analysis and assembly code export.

## 🚀 Quick Installation

1. Copy `call_tree_asm_export.py` and `my_scripts/` folder to IDA plugins directory
2. Restart IDA Pro
3. Right-click in function → "🌲 Recursive Call Tree Export"

## 📁 Project Structure

```
ida-call-tree-plugin/
├── call_tree_asm_export.py    # Main plugin - core analysis functionality
├── my_scripts/
│   ├── call_tree_window.py  # GUI viewer for saved results
│   ├── call_tree_save.py    # Data saving module
│   ├── utils.py            # Utility functions
│   ├── call_filters.json   # Filter configuration
│   ├── data/              # Output files
│   └── log/               # Debug logs
├── README.md               # This file
└── LICENSE                # MIT License
```

## ✨ Features

- 🔍 **Recursive Call Analysis** - Deep function call tree analysis
- 📊 **Visual Interface** - Interactive tree viewer
- 🎯 **Multi-Architecture** - x86/x64, ARM/ARM64 support
- 🔧 **Smart Filtering** - Custom function name aliases
- 📤 **Multiple Formats** - JSON, TXT, assembly export

## 📖 Usage

### Plugin Usage (in IDA)
1. Open binary in IDA Pro
2. Place cursor in target function
3. Right-click → "🌲 Recursive Call Tree Export"
4. View generated files in `my_scripts/data/`

### Standalone Viewer Usage
1. Install PyQt5: `pip install PyQt5`
2. Run: `python my_scripts/call_tree_window.py`
3. Open JSON file from `my_scripts/data/` folder
4. Browse call tree interactively
5. **Right-click any node** → Export sub-tree and assembly code

## 🔧 Configuration

Edit `my_scripts/call_filters.json` to customize function names:
```json
[
  {
    "ea": "401000",
    "alias": "my_function"
  }
]
```

## 📋 Requirements

- IDA Pro 7.x+
- Python 3.8+
- PyQt5 (for GUI viewer)

## 📄 License

MIT License - see [LICENSE](LICENSE) file.

---

⭐ If useful, please give a Star! 🎉
