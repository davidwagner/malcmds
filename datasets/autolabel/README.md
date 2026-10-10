# AutoLabel

Source: the three fixed Zenodo releases [15528780](https://zenodo.org/records/15528780), [15532579](https://zenodo.org/records/15532579), and [15568798](https://zenodo.org/records/15568798). `release.json` pins all 29 scenario archives and publisher MD5 checksums (136,119,439,360 bytes).

## What Suspicious means

AutoLabel propagates attack attribution through its process/network graph. Its analyzer marks certain long-lived network connections `Suspicious` when propagation reaches a connection shared by several participants that is absent from the explicitly supplied attack-connection list. This prevents confident propagation through a connection that may also carry ordinary traffic. It is weaker evidence than a direct malicious label, and is not a benign label.

For any exported exec observation whose `malicious` field is the string `Suspicious`, we use `malicious-group` and the scenario/run identifier as `group_id`. This says the execution belongs to attack-associated activity, while the released evidence does not identify that individual invocation as an attack.
