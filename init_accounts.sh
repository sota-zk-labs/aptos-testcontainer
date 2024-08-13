aptos node run-localnet --performance &
APTOS_PID="$!"

sleep 16
IFS=',' # Set the Internal Field Separator to a comma
BATCH_SIZE=10
COUNT=0
PID=""

for item in $ACCOUNTS; do
    echo "Processing: $item"
    (echo "$item" | aptos init --network local --assume-yes --profile "$item") &

    PID="$!"
    COUNT=$((COUNT + 1))
    if [ $((COUNT % BATCH_SIZE)) -eq 0 ]; then
       wait "$PID"  # Wait only for the last PID collected in this batch
       PID=""     # Reset the PID variable for the next batch
    fi
done

kill "$APTOS_PID"