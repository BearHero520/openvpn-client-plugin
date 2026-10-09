# Source profile was validated in JavaScript. Only native Android ping does DNS.
BEGIN { block = ""; failed = 0; count = 0 }
/^<[a-z-]+>$/ { block = $0 }
!block && $1 == "remote" {
    host = $2
    if (host !~ /^[A-Za-z0-9][A-Za-z0-9.-]*$/) { failed = 1; next }
    if (host !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
        command = "/system/bin/ping -c 1 -W 1 " host " 2>/dev/null"
        address = ""
        while ((command | getline answer) > 0) {
            if (answer ~ /^PING / && match(answer, /\([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\)/)) {
                address = substr(answer, RSTART + 1, RLENGTH - 2)
            }
        }
        close(command)
        if (!address) { failed = 1; next }
        $2 = address
    }
    count++
}
{ print }
/^<\/[a-z-]+>$/ { block = "" }
END { if (failed || count == 0) exit 1 }
