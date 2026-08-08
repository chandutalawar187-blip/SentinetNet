# SentinetNet

<p align="center">
  <strong>Lightweight ML-Powered Network Intrusion Detection & Blocking</strong>
</p>

<p align="center">
  Detect suspicious network activity, classify malicious traffic, generate alerts, and optionally block offending traffic — with a lightweight local architecture.
</p>

<p align="center">
  <a href="https://github.com/chandutalawar187-blip/SentinetNet/actions/workflows/contribution-ci.yml">
    <img src="https://github.com/chandutalawar187-blip/SentinetNet/actions/workflows/contribution-ci.yml/badge.svg" alt="CI">
  </a>
  <a href="https://github.com/chandutalawar187-blip/SentinetNet/actions/workflows/publish-to-github-packages.yml">
    <img src="https://github.com/chandutalawar187-blip/SentinetNet/actions/workflows/publish-to-github-packages.yml/badge.svg" alt="GitHub Packages">
  </a>
  <a href="https://github.com/chandutalawar187-blip/SentinetNet">
    <img src="https://img.shields.io/github/stars/chandutalawar187-blip/SentinetNet?style=flat-square" alt="GitHub Stars">
  </a>
  <a href="https://github.com/chandutalawar187-blip/SentinetNet/network/members">
    <img src="https://img.shields.io/github/forks/chandutalawar187-blip/SentinetNet?style=flat-square" alt="GitHub Forks">
  </a>
  <a href="https://github.com/chandutalawar187-blip/SentinetNet/issues">
    <img src="https://img.shields.io/github/issues/chandutalawar187-blip/SentinetNet?style=flat-square" alt="Issues">
  </a>
  <a href="https://github.com/chandutalawar187-blip/SentinetNet/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/chandutalawar187-blip/SentinetNet?style=flat-square" alt="License">
  </a>
  <img src="https://img.shields.io/badge/Python-3.x-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Node.js-%3E%3D14-339933?style=flat-square&logo=node.js&logoColor=white" alt="Node.js">
  <img src="https://img.shields.io/badge/Machine%20Learning-scikit--learn-F7931E?style=flat-square&logo=scikit-learn&logoColor=white" alt="scikit-learn">
  <img src="https://img.shields.io/badge/Network%20Analysis-Scapy-2C3E50?style=flat-square" alt="Scapy">
</p>

---

## Overview

**SentinetNet** is a lightweight network intrusion detection and blocking toolkit built around machine-learning-based traffic classification.

It captures network traffic, extracts flow information, runs trained models against observed traffic, generates security alerts, and can optionally take action against detected malicious activity.

The project is designed to keep the architecture simple and modular while providing multiple ways to interact with the detection engine:

* Python backend for packet capture and detection
* Machine-learning model training from CSV datasets
* Optional traffic blocking
* Web dashboard for monitoring and visualization
* JSON-based alert data
* Node.js wrapper and CLI for integration with Node applications

> **Status:** Active development
> **License:** MIT

---

## Features

| Feature                    | Description                                                             |
| -------------------------- | ----------------------------------------------------------------------- |
| 🔍 **Network Capture**     | Capture and ingest network traffic using Scapy                          |
| 🤖 **ML Detection**        | Classify network flows using trained machine-learning models            |
| 🚨 **Alert Generation**    | Produce structured alerts for suspicious traffic                        |
| 🛡️ **Traffic Blocking**   | Optionally block offending interfaces or traffic                        |
| 📊 **Web Dashboard**       | Visualize detection results and security alerts                         |
| 🧠 **Model Training**      | Train models from CSV-based network datasets                            |
| 💾 **Pretrained Models**   | Use saved models and encoders from the `models/` directory              |
| 🟢 **Node.js Integration** | Run SentinetNet from Node.js applications                               |
| 💻 **CLI Support**         | Control the detector through a command-line interface                   |
| 🌐 **Interface Selection** | Select a network interface using CLI arguments or environment variables |
| 🧪 **Automated Testing**   | Test suite with pytest and coverage support                             |
| 🔐 **Local Processing**    | Detection can run locally without requiring a cloud detection API       |

---

## Architecture

```text
                         ┌─────────────────────┐
                         │   Network Traffic   │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   Packet Capture    │
                         │      Scapy          │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   Flow Processing   │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   ML Detector       │
                         │  Trained Model      │
                         └──────────┬──────────┘
                                    │
                     ┌──────────────┴──────────────┐
                     │                             │
                     ▼                             ▼
           ┌──────────────────┐          ┌──────────────────┐
           │   Benign Traffic │          │ Malicious Traffic│
           └──────────────────┘          └─────────┬────────┘
                                                   │
                                      ┌────────────┴────────────┐
                                      │                         │
                                      ▼                         ▼
                              ┌──────────────┐          ┌──────────────┐
                              │    Alerts    │          │    Blocker   │
                              └──────┬───────┘          └──────────────┘
                                     │
                                     ▼
                              ┌──────────────┐
                              │   Dashboard  │
                              └──────────────┘
```

---

## Project Structure

```text
SentinetNet/
│
├── .github/
│   └── workflows/
│       ├── contribution-ci.yml
│       └── publish-to-github-packages.yml
│
├── backend/
│   ├── capture.py
│   ├── detector.py
│   └── blocker.py
│
├── bin/
│   └── cli.js
│
├── dashboard/
│   └── app.py
│
├── data/
│   └── *.csv
│
├── lib/
│   └── index.js
│
├── models/
│   └── *.pkl
│
├── screenshots/
│   ├── dashboard.png
│   ├── alerts.png
│   └── detection-example.png
│
├── scripts/
│
├── shared/
│
├── tests/
│
├── training/
│   └── train_model.py
│
├── CONTRIBUTING.md
├── LICENSE
├── package.json
├── requirements.txt
└── README.md
```

---

## Detection Workflow

SentinetNet follows a straightforward detection pipeline:

```text
Network Interface
       │
       ▼
Packet Capture
       │
       ▼
Flow / Feature Extraction
       │
       ▼
Machine Learning Model
       │
       ├───────────────► Benign
       │
       ▼
   Malicious
       │
       ├───────────────► Alert
       │
       └───────────────► Optional Blocking
                              │
                              ▼
                         Dashboard
```

---

## Requirements

### Python

The Python backend uses:

* Python 3.x
* Scapy
* scikit-learn
* pandas
* joblib
* Streamlit
* pytest
* pytest-cov
* flake8
* bandit

These dependencies are defined in [`requirements.txt`](requirements.txt).

### Node.js

The Node wrapper requires:

* Node.js 14 or newer

The package is currently published/configured as version `1.0.1` in `package.json`.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/chandutalawar187-blip/SentinetNet.git
cd SentinetNet
```

### 2. Create a Python virtual environment

#### Windows

```powershell
python -m venv .venv
.venv\Scripts\activate
```

#### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

---

## Train the Detection Model

If you want to train a new model using the available dataset:

```bash
python training/train_model.py
```

On Windows:

```powershell
python training\train_model.py
```

The resulting model artifacts are stored under:

```text
models/
```

> **Important:** Back up existing model files before retraining if you want to preserve the current models.

---

## Run the Detector

Start the detection engine with:

```bash
python backend/detector.py
```

Windows:

```powershell
python backend\detector.py
```

The detector loads the trained models from the `models/` directory and processes network-flow data.

---

## Capture Network Traffic

Start the capture process with:

```bash
python backend/capture.py
```

Windows:

```powershell
python backend\capture.py
```

### Select a Network Interface

You can specify an interface directly:

```bash
python backend/capture.py --iface eth0
```

Or configure it through the environment:

```bash
export SENTINET_INTERFACE=eth0
```

On Windows PowerShell:

```powershell
$env:SENTINET_INTERFACE="Ethernet"
```

If no interface is supplied, Scapy can fall back to its default interface selection.

---

## Dashboard

Start the dashboard:

```bash
python dashboard/app.py
```

Then open:

```text
http://localhost:5000
```

The dashboard provides a visual interface for inspecting detection activity and alerts.

---

## Screenshots

### Dashboard

<p align="center">
  <img src="screenshots/dashboard.png" alt="SentinetNet Dashboard" width="900">
</p>

### Alerts

<p align="center">
  <img src="screenshots/alerts.png" alt="SentinetNet Alerts" width="900">
</p>

### Detection Example

<p align="center">
  <img src="screenshots/detection-example.png" alt="SentinetNet Detection Example" width="900">
</p>

> If screenshots are not available in your checkout, these images can be removed from this section until the corresponding files are added.

---

## Node.js Integration

SentinetNet also provides a Node.js wrapper around the Python detection engine.

### Install locally

From the repository root:

```bash
npm install -g .
```

### CLI

```bash
sentinetnet --iface "eth0"
```

### Programmatic API

```javascript
const Sentinet = require('@chandutalawar187-blip/sentinetnet');

const sentinet = new Sentinet({
  iface: 'eth0',
  pythonPath: 'python'
});

sentinet.on('alert', (alert) => {
  console.log('ALERT', alert);
});

sentinet.start();
```

The Node package exposes the detector through both a CLI and a programmatic interface.

---

## Configuration

### Network Interface

SentinetNet supports interface configuration through either:

```text
--iface <interface>
```

or:

```text
SENTINET_INTERFACE
```

Example:

```bash
python backend/capture.py --iface eth0
```

or:

```bash
SENTINET_INTERFACE=eth0 python backend/capture.py
```

---

## Models

Pre-trained model artifacts are stored in:

```text
models/
```

These may include:

* Trained classifiers
* Feature encoders
* Serialized preprocessing objects
* Other model artifacts required for inference

Model files should be treated as part of the inference pipeline. Retraining the model may change detection behavior, so existing artifacts should be backed up before replacement.

---

## Alerts

SentinetNet can produce structured alert information for detected malicious activity.

Example alert data can be stored in:

```text
alerts.json
```

This data can then be consumed by the dashboard or external integrations.

---

## Testing

Run the Python test suite with:

```bash
pytest
```

With coverage:

```bash
pytest --cov
```

The repository also includes static-analysis and security tooling such as:

```bash
flake8
bandit
```

Continuous integration is configured through GitHub Actions.

---

## Security Considerations

SentinetNet is a security tool, but it should **not** be treated as a replacement for a production-grade IDS/IPS, firewall, SIEM, or endpoint security platform.

Machine-learning-based detection can produce:

* False positives
* False negatives
* Dataset-dependent classifications
* Incorrect predictions on traffic distributions not represented during training

Blocking functionality should therefore be tested carefully before being deployed on production networks.

Run network capture and blocking components with the minimum privileges required by the operating system.

---

## Use Cases

SentinetNet can be useful for:

* 🧪 Network-security experimentation
* 🎓 Security and machine-learning projects
* 🔬 Intrusion-detection research
* 🖥️ Local network monitoring
* 🤖 ML-based traffic classification experiments
* 🧰 Security tooling prototypes
* 📊 Visualizing network-security alerts
* 🔗 Integrating network detection into Node.js applications

---

## Development

The project is organized into independent components so that capture, detection, blocking, training, visualization, and integration can evolve independently.

For contribution guidelines, see:

[`CONTRIBUTING.md`](CONTRIBUTING.md)

Before submitting changes, run the available tests and validation tools:

```bash
pytest
flake8 .
bandit -r .
```

---

## Roadmap

Potential areas for future development include:

* [ ] Improved real-time flow aggregation
* [ ] Expanded attack-class coverage
* [ ] Model evaluation and benchmarking
* [ ] Real-time dashboard updates
* [ ] Improved alert filtering
* [ ] Configurable blocking policies
* [ ] More network-interface compatibility
* [ ] Containerized deployment
* [ ] REST API for external integrations
* [ ] Improved model explainability
* [ ] Additional datasets and training pipelines

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch

```bash
git checkout -b feature/your-feature
```

3. Make your changes
4. Run the test suite
5. Commit your changes

```bash
git commit -m "feat: add your feature"
```

6. Push your branch

```bash
git push origin feature/your-feature
```

7. Open a pull request

For more information, see [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## License

SentinetNet is released under the **MIT License**.

See [`LICENSE`](LICENSE) for the complete license text.

---

## Disclaimer

SentinetNet is intended for **authorized security testing, research, education, and defensive network monitoring**.

Only capture, analyze, or block traffic on systems and networks that you own or have explicit permission to administer.

---

## Author

**Chandutalawar187-blip**

GitHub:
https://github.com/chandutalawar187-blip

Project:
https://github.com/chandutalawar187-blip/SentinetNet

---

<p align="center">
  <strong>SentinetNet</strong>
  <br>
  Lightweight. Local. ML-powered network defense.
</p>
