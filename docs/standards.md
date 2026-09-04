# Standards registry

See `standards/registry.py`. Detection signals, strongest first:

1. Interface selectors (function signatures present in source or ABI).
2. Inheritance (`is ERC20`, `is Ownable`, `UUPSUpgradeable`, …).
3. Import paths (`@openzeppelin/...`).
4. Source patterns (EIP-1967 slots, `proxiableUUID`, `royaltyInfo`, …).
5. ABI function names (reduced confidence, source unavailable).

All matches carry confidence in [0, 1].
