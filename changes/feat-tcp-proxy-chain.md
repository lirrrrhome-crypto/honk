Added

- Proxy chains, like mihomo `dialer-proxy` and `type: relay`: a node entry may end in `-> <node or group>`, a subscription entry takes `dialer: <node or group>`, and a group with `policy: relay` and `relay: a -> b -> exit` dials through its members in order. TCP traverses any chain; UDP reaches Trojan and VLESS exits over the chain's stream, and SOCKS5 exits when the hops in front carry UDP. A chain never falls back to a direct connection.

Changed

- Clash subscription proxies with `dialer-proxy` or `underlying-proxy` are skipped instead of being imported as nodes that dial their server directly.
