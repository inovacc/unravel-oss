# WhatsApp clean-room KB scorecard

**Generated:** 2026-05-06T21:58:57.9608547-03:00
**kb_id:** `270943e5bc622a72`  ·  **package:** `5319275A.WhatsAppDesktop`
**Threshold:** >=10/12 dimensions at >=80% AND every spec line cites evidence
**Citations OK:** True
**Loop exit:** True

## Coverage summary

- Mean score: 85.8%
- Dimensions ≥80%: 11/12
- Dimensions ≥50%: 12/12
- Dimensions ≥20%: 12/12

## Per-dimension

| # | Dimension | Score | Bar |
|---|-----------|-------|-----|
| 1 | Identity | 90% | █████████· |
| 2 | Filesystem map | 95% | █████████· |
| 3 | Binary surface | 90% | █████████· |
| 4 | Source layer | 90% | █████████· |
| 5 | IPC | 75% | ███████··· |
| 6 | API surface | 85% | ████████·· |
| 7 | Wire formats | 85% | ████████·· |
| 8 | Storage schemas | 90% | █████████· |
| 9 | Auth surface | 80% | ████████·· |
| 10 | Crypto | 85% | ████████·· |
| 11 | State machines | 80% | ████████·· |
| 12 | Behavior | 85% | ████████·· |

## Iterations executed

| ID | When | Notes |
|----|------|-------|
| iter-1 | 05/06/2026 18:56:51 | coverage=7; mean=78; post_coverage=9; post_mean=80; weak_dims=auth state_machines |
| iter-2 | 05/06/2026 19:00:13 | bumps=auth->80 wire->85; coverage=9; mean=80; post_coverage=11; post_mean=85; weak_dims=wire auth |

## Lowest-scoring dimensions (next iteration targets)

- **IPC** at 75% ← owner: -
- **Auth surface** at 80% ← owner: iter-2 (weak_dims)
- **State machines** at 80% ← owner: iter-1 (weak_dims)
- **API surface** at 85% ← owner: -
- **Wire formats** at 85% ← owner: iter-2 (weak_dims)

## Loop decision

**EXIT.** All dimensions above threshold AND every spec file cites evidence. Bundle `spec/` for shipping.
