# Towards a Cleaner Exploit-DB: Data Quality Assessment and Automated Improvement of PoC Reports

## 1. Introduction

Exploit-DB (EDB) contains a large number of publicly available Proof-of-Concept (PoC) reports that are widely used for vulnerability analysis, validation, and security research. However, inconsistencies, missing information, inaccurate fields, and publication delays may affect the reliability and usability of these reports.

This repository provides the implementation of our framework for large-scale data quality assessment and automated improvement of Exploit-DB PoC reports.

The framework mainly contains three components:

1. **RGFP (Reasoning-Guided Few-shot Prompting)**  
   RGFP uses large language models to extract four key fields from unstructured PoC reports:

   - Type
   - Platform
   - CVE-ID
   - Date

2. **Four-dimensional Data Quality Assessment**  
   The quality of PoC reports is assessed from four dimensions:

   - Consistency
   - Completeness
   - Accuracy
   - Currentness

3. **MSVI (Multi-source Semantic Verification and Improvement)**  
   MSVI uses information from multiple vulnerability data sources to verify abnormal fields, correct Type and Platform information, and complete missing standardized headers.

The framework is designed for large-scale analysis of vulnerability reports containing both structured metadata and unstructured textual descriptions.

---

## 2. Requirements

### 2.1 Software Environment

The implementation is based on Python and MongoDB.

Recommended environment:

```text
Python >= 3.9
MongoDB >= 5.0
