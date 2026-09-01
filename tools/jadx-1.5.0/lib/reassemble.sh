#!/bin/bash
# Reassemble jadx-1.5.0-all.jar from chunks
set -e
echo "Reassembling jadx-1.5.0-all.jar from chunks..."
cat jadx-1.5.0-all.jar.part* > jadx-1.5.0-all.jar
echo "Verifying checksum..."
EXPECTED="c1290292e17ff6dcaa030d38b9173794c3eda4b844eaa90d17e82f9a8ab4429f"
ACTUAL=$(sha256sum jadx-1.5.0-all.jar | awk '{{print $1}}')
if [ "$EXPECTED" = "$ACTUAL" ]; then
  echo "SUCCESS: Checksum matches!"
else
  echo "WARNING: Checksum mismatch."
  echo "Expected: $EXPECTED"
  echo "Actual:   $ACTUAL"
  exit 1
fi
