import os

NOSTR_RELAYS = [
    r.strip()
    for r in os.environ.get(
        "NOSTR_RELAYS", "wss://relay1.orangesync.tech,wss://relay.damus.io,wss://nos.lol"
    ).split(",")
    if r.strip()
]

BLOSSOM_SERVERS = [
    s.strip()
    for s in os.environ.get(
        "BLOSSOM_SERVERS", "https://blossom.psbt.me"
    ).split(",")
    if s.strip()
]
