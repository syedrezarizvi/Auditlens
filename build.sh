#!/usr/bin/env bash
# Build AuditLens.jar without Gradle.
# Usage: ./build.sh <montoya-api.jar|classes-dir> [--test]
set -euo pipefail
API="${1:?usage: ./build.sh <montoya-api.jar|classes-dir> [--test]}"
cd "$(dirname "$0")"
rm -rf build && mkdir -p build/classes build/test dist
cp -r src/main/resources/* build/classes/
javac --release 17 -Xlint:all -d build/classes -cp "$API" $(find src/main/java -name '*.java')
jar --create --file dist/AuditLens.jar -C build/classes .
echo "Built dist/AuditLens.jar"
if [[ "${2:-}" == "--test" ]]; then
  javac --release 17 -d build/test -cp "build/classes:$API" src/test/java/ollamaat/*.java
  for t in SelfTest SmokeTest ScanTest SyncTest ExcelTest ReviewerInitTest UrlCheckTest TriageTest TriageRulesTest ExcelMultiSheetTest CvssTest FalsePositiveTest LlmBackendTest EvidenceHostTest ReportFileNameTest ComplianceTest; do java -Djava.awt.headless=true -cp "build/classes:build/test:$API" "ollamaat.$t" | tail -3; done
fi
