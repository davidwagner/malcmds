# Microsoft IoT attack command sequences

Run `./fetch` with Python 3 and curl. It downloads
`Microsoft.IoT-Dump-pwd-infected.zip` (19,754,156 bytes) from Microsoft's
[Azure-Sentinel repository](https://github.com/Azure/Azure-Sentinel/blob/048039639702f528379307aca6f6881d74b142c8/Sample%20Data/Microsoft.IoT-Dump-pwd-infected.zip),
pinned to the commit that supplied the artifact. It stays compressed and
password protected; the published password is `infected`. Fetching does not
require the password or extract anything. The script checks SHA-256 and skips
an already verified download. No Azure account is needed.

The ZIP contains `Microsoft.IoT-Dump1.json`: a JSON array, UTF-8 with a byte-order
mark (use `utf-8-sig`). The archive and a decrypted prefix were verified on
2026-10-02. It contains Unix/Linux command sequences captured by Microsoft's
IoT honeypot network during four months in 2019. The announcement describes
more than 125,000 distinct sequences observed over 150 million times. Those
observations are aggregated counts, not individually released sessions.
These are remote shell command sequences; the announcement does not establish
a kernel audit or Sysmon collection mechanism, nor guarantee that each input
successfully launched a process. There are no Windows command traces.

## Record schema

| Field | Use |
| --- | --- |
| `Commands` | Ordered array of full command strings. One string may contain pipelines, compound commands, or shell syntax. |
| `ID` | SHA-256 identifier supplied for the sample/sequence. |
| `Protocol` | Connection protocol; the inspected samples use `Telnet`. |
| `TimesSeen` | Number of observations of the sample across the sensor network. |
| `FirstSeen`, `LastSeen` | Aggregate observation timestamps; the inspected strings have fractional seconds without a timezone suffix. |

All objects represent command sequences, so no event-type filter is needed.
There is no per-command timestamp, OS process ID, user ID, or individual
connection/session identifier. `ID` groups a sequence across repeated
observations, not one login session. For individual command rows, retain `ID`
and the array index. Do not interpret first/last seen as every command's
execution time or infer an undocumented timezone.

## Labels

The publisher presents the entire collection as malware/attack activity.
This is sample-level malicious provenance; the JSON has no explicit
benign/malicious field, no separate ground-truth file, and no benign partition.
Commands such as `sh` or system inspection can appear within malicious
sequences without being uniquely malicious in isolation. Label construction
beyond the honeypot attack collection is not specified in the announcement.

The upstream repository carries an [MIT license](https://github.com/Azure/Azure-Sentinel/blob/master/LICENSE);
the archive has no separate license member. See the
[Microsoft release announcement](https://techcommunity.microsoft.com/t5/azure-sentinel/enabling-security-research-amp-hunting-with-open-source-iot/ba-p/1279037)
for collection scope and the password.
