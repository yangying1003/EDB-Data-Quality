# EDB-Data-Quality

This repository provides the source code and experimental results for our study on the data quality assessment and improvement of Exploit-DB (EDB) PoC reports.

## Overview

This study systematically assesses the data quality of Exploit-DB PoC reports from four dimensions:

- Consistency
- Completeness
- Accuracy
- Currentness

The repository contains the implementation of the proposed methods and the experimental results reported in the paper.

## Methods

The main methods include:

### RGFP
Reasoning-Guided Few-shot Prompting (RGFP) is used for LLM-based field extraction from PoC reports.

### Data Quality Assessment
The extracted information is used to assess the quality of EDB PoC reports from four dimensions:

- Consistency
- Completeness
- Accuracy
- Currentness

### MSVI
Multi-source Semantic Verification and Improvement (MSVI) is used to verify and improve abnormal or incomplete information using multiple external information sources.

## Repository Structure

```text
EDB-Data-Quality/
├── code/          # Source code
├── prompts/       # Prompts used in LLM-based processing
├── results/       # Experimental results
├── data/          # Dataset description and sample data
├── README.md
└── requirements.txt
