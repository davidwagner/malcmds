"""Reviewed ordinary browser launches in the released ATLAS collection.

Each tuple records scenario, actual procstart time, and subsequent connection
with a REAPr root_cause endpoint. These are process UUIDs, not program-name
exceptions. The native source excerpts used for review are regression fixtures.
"""

import re

BROWSER_STARTS = {
    '7DMF69PK-05e66419-000005dc-00000000-1d89b82b6c08080': ('h2-m3', '2022-07-19 15:17:52.1708513 +0000 UTC', '2022-07-19 20:33:12.9052013 +0000 UTC'),
    '7DMF69PK-05e640b8-00000d94-00000000-1d89ba2c3a14ceb': ('h2-m2', '2022-07-19 19:07:17.6564971 +0000 UTC', '2022-07-19 19:52:43.5332427 +0000 UTC'),
    '7DMF69PK-05e6cfec-000002f4-00000000-1d89bcafd04d4cf': ('h2-m6', '2022-07-19 23:55:13.8080975 +0000 UTC', '2022-07-20 00:16:11.6148468 +0000 UTC'),
    '7DMF69PK-05e6ab67-00000cb4-00000000-1d89b944c851887': ('h2-m4', '2022-07-19 17:26:20.5858362 +0000 UTC', '2022-07-19 22:55:22.3298287 +0000 UTC'),
    '7DMF69PK-05e6c10d-00000fa0-00000000-1d89bc44ae28c9b': ('h2-m5', '2022-07-19 23:11:00.3131807 +0000 UTC', '2022-07-19 23:43:00.6832399 +0000 UTC'),
    '7DMF69PK-05e61374-00000bf4-00000000-1d89b699780ab93': ('h2-m1', '2022-07-19 12:18:02.3093139 +0000 UTC', '2022-07-19 17:28:24.2422745 +0000 UTC'),
    '7DMF69PK-05e6ad40-00000c54-00000000-1d89bbfef61e268': ('h1-m4', '2022-07-19 22:36:06.4658024 +0000 UTC', '2022-07-19 22:36:08.6976064 +0000 UTC'),
    '7DMF69PK-05e6ded8-00000f3c-00000000-1d89bd058b9c425': ('h1-s4', '2022-07-20 00:33:35.1501861 +0000 UTC', '2022-07-20 00:33:36.1339879 +0000 UTC'),
    '7DMF69PK-05e6604a-00000d34-00000000-1d89bab52c95100': ('h1-m3', '2022-07-19 20:08:33.8067712 +0000 UTC', '2022-07-19 20:29:36.3438816 +0000 UTC'),
    '7DMF69PK-05e6d050-00000718-00000000-1d89bcb06740210': ('h1-m6', '2022-07-19 23:55:29.6362 +0000 UTC', '2022-07-19 23:55:31.6340036 +0000 UTC'),
    '7DMF69PK-05e5c3f1-000009cc-00000000-1d89b7b01dd33ac': ('h1-s3', '2022-07-19 14:22:42.198622 +0000 UTC', '2022-07-19 14:22:44.2900258 +0000 UTC'),
    '7DMF69PK-05e59b07-00000890-00000000-1d89b70f4572302': ('h1-s1', '2022-07-19 13:10:44.5423362 +0000 UTC', '2022-07-19 13:26:01.389204 +0000 UTC'),
    '7DMF69PK-05e5f750-0000055c-00000000-1d89b88df46bd5c': ('h1-m1', '2022-07-19 16:01:57.1242332 +0000 UTC', '2022-07-19 17:22:13.8946124 +0000 UTC'),
    '7DMF69PK-05e64e83-00000e20-00000000-1d89ba626a8a364': ('h1-m2', '2022-07-19 19:31:32.2892132 +0000 UTC', '2022-07-19 19:46:40.6811256 +0000 UTC'),
    '7DMF69PK-05e5add1-00000630-00000000-1d89b75aaf1262f': ('h1-s2', '2022-07-19 13:44:28.8839215 +0000 UTC', '2022-07-19 14:09:33.2487933 +0000 UTC'),
    '7DMF69PK-05e6c23b-00000cb8-00000000-1d89bc5842569c4': ('h1-m5', '2022-07-19 23:16:03.5336644 +0000 UTC', '2022-07-19 23:16:04.8762668 +0000 UTC'),
    '7DMF69PK-05e6c23b-00000f74-00000000-1d89bc82c2355bf': ('h1-m5', '2022-07-19 23:35:04.3707327 +0000 UTC', '2022-07-19 23:35:06.2593361 +0000 UTC'),
}


def launch_label(fields, source, program, args, label):
    """Correct only a reviewed ordinary browser launch with complete recorded text."""
    evidence = BROWSER_STARTS.get(fields.get('process_guid', ''))
    if not evidence or not fields.get('_reapr_attack') or args:
        return label
    scenario = evidence[0]
    if not source.endswith(f'edr-{scenario}.jsonl'):
        return label
    installed_path = re.sub(r"\\+", r"\\", program.lower())
    if installed_path in {r'c:\program files\mozilla firefox\firefox.exe', r'c:\program files (x86)\mozilla firefox\firefox.exe'}:
        return 'benign'
    return label
