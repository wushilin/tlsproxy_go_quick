#!/bin/sh
# cert_validate_script for an S3-compatible server with virtual-hosted buckets:
# <bucket>.<suffix> gets a certificate only if <bucket> exists right now.
#
#   [[host]]
#   pattern = *.s3.example.com                  # one label: the bucket
#   cert = auto
#   cert_validate_script = /usr/local/etc/tlsproxy/s3-bucket-admission.sh
#   target_host = 192.168.1.50
#   target_port = 9000
#   upstream_tls = false
#
# tlsproxy runs it as `s3-bucket-admission.sh <name>` only when a certificate
# has to be issued or renewed, and logs the exit status and what is printed:
#   0  the bucket exists: issue / renew
#   1  not a bucket of ours (or not a name of this form): no certificate
#   2  could not find out (server down, bad credentials, unexpected answer):
#      also no certificate; a renewal keeps the current one and asks again later
#
# Settings come from s3-bucket-admission.conf next to this script (or the file
# named by $S3_ADMISSION_CONF). Keep it mode 0600: it holds the secret key.
#   ENDPOINT=http://192.168.1.50:9000
#   REGION=us-east-1
#   SUFFIX=s3.example.com
#   ACCESS_KEY=...
#   SECRET_KEY=...
#   CACHE_SECONDS=60      # optional; 0 = ask the server every time
#
# The bucket list is kept for CACHE_SECONDS (in a mode 0600 file next to this
# script), so a flood of made-up names costs the S3 server one request a
# minute, not one per name. A new bucket is therefore seen up to a minute late.
#
# Needs curl >= 7.75 (--aws-sigv4) and xmllint (libxml2). The bucket list is
# parsed as XML, not searched as text, and the key never appears on a command
# line (curl reads it from stdin), so it is not visible in `ps`.

set -u
PATH=/usr/local/bin:/usr/bin:/bin

conf=${S3_ADMISSION_CONF:-$(dirname "$0")/s3-bucket-admission.conf}
if [ ! -r "$conf" ]; then
	echo "cannot read $conf"
	exit 2
fi
. "$conf"

name=$(printf '%s' "${1:-}" | tr 'A-Z' 'a-z')
case "$name" in
*".$SUFFIX") bucket=${name%".$SUFFIX"} ;;
*)
	echo "$name is not under .$SUFFIX"
	exit 1
	;;
esac

# Bucket naming rules. No dots: a dot would be a further label, which the
# pattern does not match anyway. This also keeps the name safe to put in XPath.
case "$bucket" in
"" | *[!a-z0-9-]* | -* | *-)
	echo "'$bucket' is not a valid bucket name"
	exit 1
	;;
esac
if [ ${#bucket} -lt 3 ] || [ ${#bucket} -gt 63 ]; then
	echo "'$bucket' is not a valid bucket name (3 to 63 characters)"
	exit 1
fi

# ListBuckets, signed with SigV4; or the copy from less than CACHE_SECONDS ago.
cache=$(dirname "$0")/.s3-bucket-admission.cache
ttl=${CACHE_SECONDS:-60}
source=$ENDPOINT
if [ "$ttl" -gt 0 ] && [ -f "$cache" ] && [ $(($(date +%s) - $(stat -c %Y "$cache" 2>/dev/null || stat -f %m "$cache"))) -lt "$ttl" ]; then
	xml=$(cat "$cache")
	source="$ENDPOINT, cached"
else
	xml=$(printf 'user = "%s:%s"\n' "$ACCESS_KEY" "$SECRET_KEY" |
		curl -K - -sS --fail --max-time 10 --aws-sigv4 "aws:amz:$REGION:s3" "$ENDPOINT/" 2>&1) || {
		echo "cannot list the buckets at $ENDPOINT: $xml"
		exit 2
	}
	if [ "$ttl" -gt 0 ]; then # written whole, then renamed: never read half a list
		(umask 077 && printf '%s' "$xml" >"$cache.$$" && mv "$cache.$$" "$cache") 2>/dev/null
	fi
fi

# --nonet: never fetch anything the document refers to. Entities are not expanded.
xpath() { printf '%s' "$xml" | xmllint --nonet --xpath "$1" - 2>/dev/null; }

root=$(xpath 'local-name(/*)')
if [ "$root" != "ListAllMyBucketsResult" ]; then
	rm -f "$cache"
	echo "unexpected answer from $ENDPOINT (root element '${root:-not XML}')"
	exit 2
fi
buckets="/*[local-name()='ListAllMyBucketsResult']/*[local-name()='Buckets']/*[local-name()='Bucket']"
total=$(xpath "count($buckets)")
found=$(xpath "boolean($buckets/*[local-name()='Name'][normalize-space(.)='$bucket'])")

if [ "$found" = "true" ]; then
	echo "bucket '$bucket' exists ($total buckets at $source)"
	exit 0
fi
echo "no bucket '$bucket' ($total buckets at $source)"
exit 1
