#!/bin/sh
# SAMPLE FILE. The password is made up.

curl -s https://admin:Hunter2Hunter2@files.internal.example/backup.tar.gz -o backup.tar.gz

# This one is a known test value, so the scanner is told to skip it:
TEST_KEY="Tr0ub4dor&3xyz"  # secrets-scanner: ignore

