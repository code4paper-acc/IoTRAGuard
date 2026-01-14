# Extractor

**Extractor** is used to fetch vulnerability records related to **Zephyr OS** from the NVD vulnerability database and build the **IoTRAGuard & CodeGuarder** security knowledge base.

## 🛠️ Prerequisites

* Python 3.10+

* Joern: 4.0+. Get [Joern](https://github.com/joernio/joern.git) and place it in the `joern` directory.

* Target Repository: You must have the [Zephyr](https://github.com/zephyrproject-rtos/zephyr.git) repository (or target repo) cloned locally.

## 📦 Installation
```bash
# Install dependencies
conda create -n extractor python=3.10
cd extractor
pip install -r requirements.txt
```

## 🚀 Usage
### Step 1: Fetch vulnerability records
```bash
python cve_analyzer.py
```
### Step 2: Build security knowledge base
```bash
python sec_database_extractor.py
```
The safety knowledge base will be output in the `datasets` directory