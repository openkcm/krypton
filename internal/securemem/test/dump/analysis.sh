#!/bin/sh

apk update >/dev/null 2>&1
apk add gdb >/dev/null 2>&1

cleanup() {
  # Cleanup
  rm $TRIGGER_NAME
  rm secret_$TRIGGER_NAME
  rm start_$TRIGGER_NAME
  rm core.${pid}
  echo "FINISHED"
  exit 0
}

trap cleanup TERM INT QUIT

UNEXPOSED_SECRET=MYSECRETKEY123458901234567890123
EXPOSED_SECRET=EXPOSED_SECRET123456789012345678

set +x
cd /app

echo "👷 Building secret-runner"
GOEXPERIMENT=runtimesecret go build -o ./tmp/$TRIGGER_NAME internal/securemem/test/dump/main.go
echo "🚀 Starting secret-runner in the background..."

# Change to the secret-runner directory
cd ./tmp

# Write the unexposed secret to a file that secret-runner will read
echo $UNEXPOSED_SECRET >secret_$TRIGGER_NAME

# Start the secret-runner in the background
./$TRIGGER_NAME &

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
wait_for_file start_$TRIGGER_NAME

# Get the PID of the secret-runner process
pid=$(pgrep $TRIGGER_NAME)
echo "PID: $pid"

# Dump the core of the secret-runner process
echo "DUMPING CORE"
gcore -o core ${pid} >/dev/null 2>&1
echo " 🔎 SEARCHING FOR SECRET"
echo "-----------------------"
strings core.${pid} | grep $UNEXPOSED_SECRET | xargs -I {} echo "☣️ ALERT UNEXPOSED SECRET FOUND: {}"
strings core.${pid} | grep $EXPOSED_SECRET | xargs -I {} echo "✅ EXPOSED SECRET FOUND: {}"

# Search the memory maps of the secret-runner process for readable segments and dump them to find the unexposed secret
grep " r" /proc/${pid}/maps | while read line; do
  echo $line
  RANGE=$(echo "$line" | awk '{print $1}')
  START=$((0x$(echo "$RANGE" | cut -d- -f1)))
  END=$((0x$(echo "$RANGE" | cut -d- -f2)))
  LEN=$((END - START))
  [ "$LEN" -gt 67108864 ] && continue
  dd if=/proc/${pid}/mem bs=1 skip=${START} count=${LEN} 2>/dev/null | strings | grep $UNEXPOSED_SECRET | xargs -I {} echo "☣️ ALERT DUMP UNEXPOSED SECRET FOUND: {}"
done

kill $pid

sleep 5

# Cleanup
cleanup
