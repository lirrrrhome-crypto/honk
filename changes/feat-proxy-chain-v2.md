Added

- Chain nodes: `name: chain { a -> b -> out }` and arrow sugar `name: 'link' -> hop` dial through their members left to right, each member handshaking directly on the stream of the member before it. Groups take `exit: <node or group>`, serving every member through that exit. Chains carry TCP and never fall back to a direct connection.
- Clash subscription proxies with `dialer-proxy` or `underlying-proxy` are now skipped instead of being imported as nodes that dial their server directly.
