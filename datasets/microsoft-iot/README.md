# Microsoft IoT attack command sequences

Unix/Linux shell command sequences captured by Microsoft's IoT honeypot network during four months in 2019. The collection contains more than 125,000 distinct sequences seen over 150 million times. Repeated occurrences of a sequence are combined into one record with a count and the first and last times it appeared.

`Microsoft.IoT-Dump1.json` contains a JSON array of sequence records. Every record contains commands.

## Fields

| Field | Meaning |
| --- | --- |
| `Commands` | Ordered array of full command strings. A string can include pipelines, multiple commands, and other shell syntax. |
| `ID` | SHA-256 identifier for the sequence. This ID and a command's array position identify that command within the sequence. |
| `FirstSeen`, `LastSeen` | First and last times the sequence appeared. The timestamps contain fractional seconds and have no timezone suffix. |

The data has no individual connection/session ID or per-command timestamp.

## Labels

Microsoft describes the collection as malware and attack activity. That classification applies to the collected sequences, and each sequence's commands are grouped under its `ID`. The JSON has no separate malicious/benign field, and the collection has no benign partition.

Sources: [Microsoft release announcement](https://techcommunity.microsoft.com/t5/azure-sentinel/enabling-security-research-amp-hunting-with-open-source-iot/ba-p/1279037), [dataset in Azure-Sentinel](https://github.com/Azure/Azure-Sentinel/blob/048039639702f528379307aca6f6881d74b142c8/Sample%20Data/Microsoft.IoT-Dump-pwd-infected.zip).
