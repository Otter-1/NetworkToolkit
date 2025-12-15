#!/bin/bash

# $1 = Subnet (e.g. 192.168.1)
# $2 = Filename (e.g. results)

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Error: Missing arguments."
    echo "Usage: $0 <subnet> <filename>"
    exit 1
fi

SUBNET=$1
FILE="$2.txt"

echo "Scanning target subnet: $SUBNET.x"
echo "Saving to: $FILE"

# Create/Clear the file
echo "00--- Available IPs ---00" > "$FILE"

# Run pings in parallel
for ip in {1..254}; do
    (
        ping -c 1 -W 1 "$SUBNET.$ip" | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" >> "$FILE"
    ) &
done

# Wait for all background pings to finish
wait

# Sort the file naturally
sort -V "$FILE" -o "$FILE"

echo "Scan complete."
cat "$FILE"
