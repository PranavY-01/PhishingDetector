#  Phishing Email Detector (CLI-Based)

A simple command-line tool to detect and analyze potential phishing emails by parsing `.eml` files and checking for known phishing indicators.

##  Features

- Parses `.eml` files using Python’s email module.
- Detects suspicious patterns in:
  - Email headers (`From`, `Reply-To`, `Return-Path`)
  - URLs in the body
  - Phishing-related keywords
- Assigns a
