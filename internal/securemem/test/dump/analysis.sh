#!/bin/sh

# This script is used to test the dump protection of the secret-runner application.
# It will start the secret-runner in the background, wait for it to create a "start" file,
# and then attempt to dump the memory of the secret-runner process to find the unexposed
# secret. Finally, it will clean up any files created during the test.

apk update >/dev/null 2>&1
apk add gdb >/dev/null 2>&1

# cleanup function to remove any files created during the test
cleanup() {
  # Cleanup
  rm -f "$TRIGGER_ID"
  rm -f "secret_${TRIGGER_ID}"
  rm -f "exposed_${TRIGGER_ID}"
  rm -f "start_${TRIGGER_ID}"
  rm -f "core.${pid}"
  echo "FINISHED"
  exit 0
}

trap cleanup TERM INT QUIT

SECUREMEM_SECRET=MYSECRETKEY123458901234567890123
UNSECURED_SECRET=EXPOSED_SECRET123456789012345678

set +x
cd /app

echo "👷 Building secret-runner"
GOEXPERIMENT=runtimesecret go build -o ./tmp/$TRIGGER_ID internal/securemem/test/dump/main.go
echo "🚀 Starting secret-runner in the background..."

# Change to the secret-runner directory
cd ./tmp

# Write the unexposed secret to a file that secret-runner will read
echo $SECUREMEM_SECRET >secret_$TRIGGER_ID

# Write the unexposed secret to a file that unsecret-runner will read
echo $UNSECURED_SECRET >exposed_$TRIGGER_ID

# Start the secret-runner in the background
./$TRIGGER_ID &

# Function to wait for a file to be created with a timeout
wait_for_file() {
  FILE=$1
  TIMEOUT=${2:-10} # default 10 seconds
  INTERVAL=${3:-2} # check every 2 second
  ELAPSED=0

  echo "⏳ Waiting for file: $FILE (timeout: ${TIMEOUT}s)"

  while [ ! -f "$FILE" ]; do
    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
      echo "❌ Timeout! File not found: $FILE"
      return 1
    fi
    sleep "$INTERVAL"
    ELAPSED=$((ELAPSED + INTERVAL))
    echo "   ... waiting ${ELAPSED}s"
  done

  echo "✅ File found: $FILE (after ${ELAPSED}s)"
  return 0
}

# Wait for the "start" file to be created by secret-runner
wait_for_file start_$TRIGGER_ID

# Get the PID of the secret-runner process
pid=$(pgrep $TRIGGER_ID)
echo "PID: $pid"

# Dump the core of the secret-runner process
echo "DUMPING CORE"
gcore -o core ${pid} >/dev/null 2>&1
echo " 🔎 SEARCHING FOR SECRET"
echo "-----------------------"
strings core.${pid} | grep $SECUREMEM_SECRET | xargs -I {} echo "☣️ ALERT SECUREMEM SECRET FOUND: {}"
strings core.${pid} | grep $UNSECURED_SECRET | xargs -I {} echo "✅ UNSECURED SECRET FOUND: {}"

# Check if dump protection is enabled and if so, attempt to dump the memory
# of the secret-runner process to find the unexposed secret
if [ "$IS_DUMP_PROTECTION_ENABLED" = "true" ]; then
  echo "RUNNING DUMP PROTECTION TEST"
  # Search the memory maps of the secret-runner process for readable segments and dump them to find the unexposed secret
  grep " r" /proc/${pid}/maps | while read line; do
    echo $line
    RANGE=$(echo "$line" | awk '{print $1}')
    START=$((0x$(echo "$RANGE" | cut -d- -f1)))
    END=$((0x$(echo "$RANGE" | cut -d- -f2)))
    LEN=$((END - START))
    [ "$LEN" -gt 67108864 ] && continue
    dd if=/proc/${pid}/mem bs=1 skip=${START} count=${LEN} 2>/dev/null | strings | grep $SECUREMEM_SECRET | xargs -I {} echo "☣️ ALERT SECUREMEM SECRET FOUND: {}"
  done

fi

kill $pid

sleep 5

# Cleanup
cleanup
