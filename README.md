# Towards a Cleaner Exploit-DB: Large-Scale Assessment and Automated Improvement of PoC Report Quality

## 1. Introduction

Exploit-DB (EDB) contains a large number of publicly available Proof-of-Concept (PoC) reports that are widely used for vulnerability analysis, validation, reproduction, and security research. However, inconsistencies, missing information, inaccurate fields, and publication delays may affect the reliability and usability of these reports.

This repository provides the implementation of our framework for the large-scale data quality assessment and automated improvement of Exploit-DB PoC reports.

The framework mainly contains three components:

1. **RGFP (Reasoning-Guided Few-shot Prompting)**  
   RGFP uses large language models (LLMs) to extract four key fields from unstructured PoC reports:
   - Type
   - Platform
   - CVE-ID
   - Date

2. **Four-dimensional Data Quality Assessment**  
   The quality of PoC reports is assessed from four dimensions:
   - Consistness
   - Completeness
   - Accuracy
   - Currentness

3. **MSVI (Multi-source Semantic Verification and Improvement)**  
   MSVI uses information from multiple vulnerability data sources to verify abnormal fields, correct Type and Platform information, and complete missing standardized headers.

The overall workflow is:

```text
PoC Reports
    |
    v
Preprocessing
    |
    v
RGFP-based Field Extraction
    |
    v
Four-dimensional Data Quality Assessment
    |
    v
MSVI-based Verification and Improvement
```

---

## 2. Requirements

### 2.1 Software Environment

The implementation is based on Python and MongoDB.

Recommended environment:

```text
Python >= 3.9
MongoDB >= 5.0
```

MongoDB is used to store and process PoC reports, extracted fields, external vulnerability information, intermediate data, and assessment results.

Large language models are required for RGFP-based field extraction and semantic processing.

### 2.2 Python Dependencies

Install the required Python packages using:

```bash
pip install -r requirements.txt
```

The main dependencies include:

```text
pymongo
Pygments
tree-sitter
requests
```

Additional packages may be required depending on the selected LLM or API provider.

### 2.3 MongoDB Configuration

Before running the scripts, install and start MongoDB.

A typical local MongoDB connection is:

```text
mongodb://localhost:27017/
```

Example configuration:

```text
MONGODB_URI=mongodb://localhost:27017/
MONGODB_DATABASE=edb
```

The actual database name and collection names should be configured according to the local environment and the corresponding scripts.

### 2.4 Large Language Model Configuration

Large language models are used in RGFP-based field extraction and related semantic processing tasks.

The experiments in the paper evaluate the following representative models:

```text
Llama3.1:8b
DeepSeek-R1:14b
Qwen3.5-plus
```

Before running LLM-related scripts, configure the corresponding model service.

Example configuration:

```text
LLM_API_KEY=your_api_key
LLM_BASE_URL=your_api_endpoint
LLM_MODEL=your_model_name
```

If a locally deployed model is used, configure the local model path or inference endpoint instead.

> **Important:** Do not upload API keys, passwords, database credentials, or other private information to GitHub.

---

## 3. Repository Structure

The repository is organized as follows:

```text
EDB-Data-Quality/
│
├── .gitattributes
├── .gitignore
├── README.md
│
├── code/
│   │
│   ├── assessment/
│   │   │
│   │   ├── accuracy/
│   │   │   ├── alerted_platform.py
│   │   │   └── alerted_type.py
│   │   │
│   │   ├── completeness/
│   │   │   ├── code_detect.py
│   │   │   └── entry_detect.py
│   │   │
│   │   ├── consistnetness/
│   │   │   ├── compare_cve.py
│   │   │   ├── compare_platform.py
│   │   │   └── compare_type.py
│   │   │
│   │   ├── currentness/
│   │   │   ├── CDF_lagtime.py
│   │   │   └── compare_date.py
│   │   │
│   │   └── timeness/
│   │
│   ├── MSVI/
│   │   ├── add_author.py
│   │   ├── add_cve.py
│   │   ├── add_date.py
│   │   ├── add_google.py
│   │   ├── add_software.py
│   │   ├── add_test.py
│   │   ├── add_title.py
│   │   ├── add_vendor.py
│   │   ├── add_version.py
│   │   ├── repair_platform.py
│   │   └── repair_type.py
│   │
│   └── RGFP/
│       ├── extract_date.py
│       ├── platform_CVE.py
│       └── Type.py
│
├── data/
│   ├── EDB.edb_data.csv
│   ├── Labeled_EDB_first_500.csv
│   ├── Multiple_DB.platform_verify_270.csv
│   ├── Multiple_DB.type_verify_270.csv
│   └── Verify_complete.collection_repairverify.csv
│
└── results/
    ├── EDB_repairresult.EDB_platformresult.csv
    ├── EDB_repairresult.EDB_typeresult.csv
    └── Verify_complete.added_verify300.csv

Directory Descriptions: 
code/assessment/accuracy/: scripts for detecting potential accuracy problems in the Type and Platform fields.
code/assessment/completeness/: scripts for detecting standardized headers and identifiable code in PoC reports.
code/assessment/consistnetness/: scripts for comparing CVE-ID, Platform, and Type between structured fields and extracted report content.
code/assessment/currentness/: scripts for date comparison and publication-delay analysis.
code/MSVI/: scripts for Type and Platform correction and missing-header completion using MSVI.
code/RGFP/: scripts for LLM-based extraction of Type, Platform, CVE-ID, and Date from PoC report text.
data/: datasets and manually verified samples used in the experiments.
results/: field-correction and header-completion results generated by the proposed method.

---

## 4. Usage

### 4.1 Step 1: Preprocess PoC Reports

PoC reports may contain URLs, redundant spaces, empty lines, and consecutive special characters.

The preprocessing module removes noisy information before field extraction.

The corresponding scripts are located in:

```text
code/preprocessing/
```

Before execution, configure the MongoDB connection or input file path according to the corresponding script.

---

### 4.2 Step 2: RGFP-based Field Extraction

RGFP extracts the following fields from the unstructured text of PoC reports:

```text
CVE-ID
Type
Platform
Date
```

The implementation is located in:

```text
code/RGFP/
```

Before execution:

1. Start MongoDB if the script reads from or writes to MongoDB.
2. Configure the LLM API or local model.
3. Configure the input collection, output collection, or input file path.
4. Run the corresponding RGFP extraction script.

The extraction results are stored in MongoDB or exported as structured files for subsequent assessment.

---

### 4.3 Step 3: Consistency Assessment

Consistency assessment compares information extracted from unstructured PoC text with the structured fields provided by EDB.

The following fields are evaluated:

```text
Type
Platform
CVE-ID
```

The corresponding implementation is located in:

```text
code/assessment/consistency/
```

The output contains the consistency status of the assessed fields, including cases such as consistent, under-covered, inconsistent, or missing where applicable.

---

### 4.4 Step 4: Completeness Assessment

Completeness assessment evaluates whether a PoC report contains the required standardized headers and identifiable exploit code.

Nine standardized information headers are considered:

```text
Exploit Title
Date
Exploit Author
CVE
Vendor Homepage
Software Link
Version
Tested on
Google Dork
```

Regular expressions are used for header detection.

Pygments and Tree-sitter are used together with heuristic rules to identify code fragments in PoC reports.

The corresponding implementation is located in:

```text
code/assessment/completeness/
```

For example, the code-presence detection script can be executed as:

```bash
python code/assessment/completeness/code_presence_detection.py <input_file>
```

Example:

```bash
python code/assessment/completeness/code_presence_detection.py poc1.txt
```

The script determines whether the input PoC report contains identifiable code and outputs the corresponding diagnostic information.

---

### 4.5 Step 5: Accuracy Assessment

Accuracy assessment compares EDB fields with information from multiple external vulnerability databases.

The external data sources include:

```text
CVE
NVD
CNNVD
```

CVE-ID is used as the association key.

The Type and Platform fields are normalized into a unified label space and evaluated using cross-source comparison and a reward-punishment matrix.

The corresponding implementation is located in:

```text
code/assessment/accuracy/
```

Before execution, make sure that the required external vulnerability data have been imported into MongoDB or are available through the configured local data source.

---

### 4.6 Step 6: Currentness Assessment

Currentness measures the publication delay of PoC reports.

The Date extracted from the report text is compared with the publication date recorded in EDB.

The corresponding implementation is located in:

```text
code/assessment/currentness/
```

The output can be used to calculate publication-delay statistics and interval distributions.

---

### 4.7 Step 7: MSVI-based Data Quality Improvement

MSVI performs automated improvement based on the results of consistency, completeness, and accuracy assessment.

The method mainly contains two tasks:

1. **Type and Platform correction**
2. **Missing-header completion**

For field correction, MSVI combines evidence from:

```text
EDB structured fields
PoC text extraction results
CVE
NVD
CNNVD
```

A candidate correction is applied only when sufficient multi-source evidence is available.

The implementation is located in:

```text
code/MSVI/
```

Before execution:

1. Complete the required assessment steps.
2. Ensure the external vulnerability data are available.
3. Configure the MongoDB collections or input files.
4. Run the corresponding MSVI scripts for field correction or header completion.

---

## 5. Data

The PoC reports used in this study were collected from Exploit-DB.

The study uses 47,582 parseable PoC reports after preprocessing and filtering.

The complete raw PoC collection is not redistributed directly in this repository.

The `data/` directory provides:

```text
dataset descriptions
sample records
data preprocessing information
field definitions
```

External vulnerability information used for cross-source assessment is obtained from:

```text
CVE
NVD
CNNVD
```

---

## 6. Main Results

The main experimental results reported in the paper are summarized below.

### 6.1 RGFP Field Extraction

| Model | Prompting Method | Type | Platform | CVE-ID | Date | Average |
|---|---|---:|---:|---:|---:|---:|
| Llama3.1:8b | RGFP | 89.8% | 88.5% | 91.0% | 91.1% | 90.1% |
| DeepSeek-R1:14b | RGFP | 84.6% | 82.8% | 86.0% | 86.6% | 85.0% |
| Qwen3.5-plus | RGFP | **93.8%** | **92.5%** | **95.4%** | **95.1%** | **94.2%** |

### 6.2 Data Quality Assessment

| Dimension | Main Result |
|---|---|
| Consistency – Type | 11.60% consistent, 77.44% under-covered, and 10.96% inconsistent |
| Consistency – Platform | 57.41% consistent, 18.64% under-covered, 18.70% inconsistent, and 5.25% missing |
| Completeness – Headers | 1,255 of 47,582 reports (2.64%) contain all nine standardized headers |
| Completeness – Code | 21,308 reports (44.78%) contain identifiable exploit code |
| Accuracy – Type | 23,478 reports trigger Type alerts; overall alert precision is 94.22% |
| Accuracy – Platform | 1,727 reports trigger Platform alerts; overall alert precision is 84.57% |
| Currentness | 27,609 reports have comparable dates; 49.18% exhibit delayed inclusion |
| Currentness – Non-negative Delay | 73.49% are included within 7 days; the average delay is 68.27 days |

### 6.3 Standardized Header Inclusion Rates

| Header | Inclusion Rate |
|---|---:|
| Exploit Title | 27.59% |
| Google Dork | 9.28% |
| Date | 27.89% |
| Exploit Author | 37.74% |
| Vendor Homepage | 24.23% |
| Software Link | 25.61% |
| Version | 26.44% |
| Tested on | 22.18% |
| CVE | 11.84% |

### 6.4 MSVI Improvement

| Field | State | Before | After |
|---|---|---:|---:|
| Type | Consistent | 11.60% | 12.42% |
| Type | Under-covered | 77.44% | 78.22% |
| Type | Inconsistent | 10.96% | 9.36% |
| Platform | Consistent | 57.41% | 60.30% |
| Platform | Under-covered | 18.64% | 18.55% |
| Platform | Missing | 5.25% | 5.25% |
| Platform | Inconsistent | 18.70% | 15.90% |

MSVI corrects **2,963 Type fields** and **1,359 Platform fields**.

For header completion, the masking-and-recovery experiment produces 1,394 valid completions from 1,800 masked instances, corresponding to a valid completion rate of **77.44%**. Among the valid completions, 1,368 are manually verified as correct, resulting in an accuracy of **98.13%**.

When applied to the full dataset, 46,327 reports contain at least one missing header, involving 326,983 missing header instances. MSVI generates 244,533 valid completions, corresponding to an overall valid completion rate of **74.78%**.

Detailed output files are provided in:

```text
results/
```
---
