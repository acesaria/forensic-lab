# Score Report

Candidate input: detection_claims

## Candidate Diagnostics

Detector/candidate-layer diagnostics only. These are not final thesis reconstruction metrics.

- Candidate TP: 10
- Candidate FP: 195
- Candidate FN: 0
- Candidate precision: 0.0488
- Candidate recall: 1.0000
- Candidate F1: 0.0930

## Reconstruction over Expected Artifacts

Headline thesis reconstruction uses expected artifacts as the denominator. Class-only support is reported separately and does not increase strong instance recall.

- Expected artifacts: 10
- Observable expected artifacts: 10
- Strong instance matched expected artifacts: 7
- Class-only/support expected artifacts: 3
- Missed expected artifacts: 0
- Strong instance recall: 0.7000
- Class support coverage: 0.3000
- Strong-or-supported coverage: 1.0000
- Critical strong instance recall: 0.6

## Source Coverage

Source coverage is based on strong instance matches and their linked source findings.

- Available raw sources: disk, memory, timeline
- Candidate sources: disk, memory, timeline
- Strong reconstruction sources: disk, memory
- Source coverage ratio: 0.6667
- Denominator: available_sources from raw ToolFinding records

## Multi-Source Corroboration

Counts distinct linked source types per strong reconstructed expected artifact.

- Strong reconstructed with 2+ sources: 0
- Strong reconstructed total: 7
- Multi-source corroboration rate: 0.0000

## Noise Reduction

Count reduction only; this is not baseline-aware.

- Raw findings: 7670
- Candidate claims: 205
- Strong instance matches: 7
- Raw-to-candidate reduction: 0.9733
- Raw-to-strong-reconstruction reduction: 0.9991

## Baseline Comparison

Clean-baseline comparison is conservative support metadata. It does not infer maliciousness and does not change matcher formulas.

- Baseline available: True
- Baseline input: lab-ubuntu-22.04:baseline
- Baseline paths: 67262
- Compromised paths compared: 340
- New vs baseline paths: 16
- Changed vs baseline paths: 0
- Present in baseline paths: 324
- Unknown baseline status paths: 0
- Candidate downgrades: 66
- Candidate suppressions: 0

Limitations:

- Path-only baseline comparison is candidate support, not a maliciousness verdict.
- Present-in-baseline timeline-only candidates are confidence-downgraded, not removed.
- Baseline metadata does not affect matcher formulas or strong reconstruction by itself.

## Methodological Warnings / Unavailable Metrics

- final_reconstruction.precision label: strict_candidate_stream_precision
- final_reconstruction.precision warning: denominator includes unmatched candidate claims and class-only support; do not present as final reconstruction precision
- candidate_diagnostics are detector/candidate-stream diagnostics, not final thesis reconstruction metrics
- final_reconstruction.precision is exposed as strict_candidate_stream_precision; unmatched candidate claims remain in its denominator
- pipeline_runtime_seconds is not emitted because the canonical full pipeline runtime is not explicitly measured in cached artifacts
- evidence_latency is not emitted because reliable GT action timestamps and artifact timestamps are not paired here
- noise_reduction is raw-to-candidate and raw-to-strong-count reduction only; it is not baseline-aware

## Class-level coverage

Did an expectation's artifact class show up at all (instance or class match)?

- Class-level recall: 1.0000 (10/10)
- Class matches: 3

## Instance-level reconstruction

Did we recover the exact planted entity? Class hits count only as support. No final-claim precision is emitted because there is no final-claim selection layer.

- Strong instance recall: 0.7000
- Instance matches: 7

## Critical observables

- Critical strong instance recall: 0.6
- Candidate-supported critical recall (diagnostic): 1.0000 (5/5)

## Raw ToolFinding Counts by Source/Type

| source | artifact class | count |
|---|---|---:|
| disk | deleted_file_candidate | 3 |
| disk | file | 21 |
| disk | preload_configuration | 3 |
| disk | shared_object | 1 |
| disk | shell_history_log_event | 3 |
| memory | file | 759 |
| memory | library_mapping | 3291 |
| memory | process | 265 |
| memory | socket | 274 |
| timeline | file | 284 |
| timeline | preload_configuration | 16 |
| timeline | service_unit_file | 39 |
| timeline | shared_object | 7 |
| timeline | shell_history_log_event | 2704 |

## Candidate Evidence / DetectionClaim Counts

| rule | source | count |
|---|---|---:|
| flab.filesystem.deleted_artifact_cleanup | disk | 3 |
| flab.filesystem.ld_preload_configuration | disk | 13 |
| flab.filesystem.ld_preload_configuration | timeline | 56 |
| flab.filesystem.suspicious_shared_object | disk | 1 |
| flab.filesystem.suspicious_temp_path | disk | 17 |
| flab.filesystem.suspicious_temp_path | timeline | 68 |
| flab.filesystem.userland_persistence | timeline | 42 |
| flab.memory.process_library_correlation | memory | 1 |
| flab.memory.process_socket_correlation | memory | 4 |

## Memory Aggregation/Deduplication Summary

| rule | before | after | collapsed |
|---|---:|---:|---:|
| flab.memory.process_library_correlation | 10 | 1 | 9 |
| flab.memory.process_socket_correlation | 8 | 4 | 4 |

## Matched Expectations / Reconstruction Evidence

| strength | expectation | candidate | sources | score | fields |
|---|---|---|---|---:|---|
| strong_instance_match | AE-father-hiding-marker | dc-000032-2e468c3d24 | disk | 0.8500 | artifact_class, source_type, attck, path |
| strong_instance_match | AE-father-library-mapping | dc-000200-51b40618c7 | memory | 0.8500 | artifact_class, source_type, attck, path |
| strong_instance_match | AE-father-preload-config | dc-000013-52e687fe81 | disk | 0.8500 | artifact_class, source_type, attck, path |
| strong_instance_match | AE-father-shared-object | dc-000072-d70bac66ab | disk | 0.8500 | artifact_class, source_type, attck, path |
| strong_instance_match | AE-father-source-file | dc-000062-7dfda83cb5 | disk | 0.8500 | artifact_class, source_type, attck, path |
| strong_instance_match | AE-father-source-metadata | dc-000067-347c378996 | disk | 0.8500 | artifact_class, source_type, attck, path |
| strong_instance_match | AE-father-upstream-archive | dc-000057-ad33a78d3c | disk | 0.8500 | artifact_class, source_type, attck, path |
| class_only_support | AE-father-benign-process | dc-000201-68a1ce66d8 | memory | 0.6000 | artifact_class, source_type, attck |
| class_only_support | AE-father-cleanup-deleted-marker | dc-000000-a91c10a774 | disk | 0.6000 | artifact_class, source_type, attck |
| class_only_support | AE-father-shell-log | dc-000003-3bfcdeed09 | disk | 0.6000 | artifact_class, source_type, attck |

## Strong Instance Matches

| expectation | candidate | sources | score | fields |
|---|---|---|---:|---|
| AE-father-hiding-marker | dc-000032-2e468c3d24 | disk | 0.8500 | artifact_class, source_type, attck, path |
| AE-father-library-mapping | dc-000200-51b40618c7 | memory | 0.8500 | artifact_class, source_type, attck, path |
| AE-father-preload-config | dc-000013-52e687fe81 | disk | 0.8500 | artifact_class, source_type, attck, path |
| AE-father-shared-object | dc-000072-d70bac66ab | disk | 0.8500 | artifact_class, source_type, attck, path |
| AE-father-source-file | dc-000062-7dfda83cb5 | disk | 0.8500 | artifact_class, source_type, attck, path |
| AE-father-source-metadata | dc-000067-347c378996 | disk | 0.8500 | artifact_class, source_type, attck, path |
| AE-father-upstream-archive | dc-000057-ad33a78d3c | disk | 0.8500 | artifact_class, source_type, attck, path |

## Class-Only / Support Matches

| expectation | candidate | sources | score | fields |
|---|---|---|---:|---|
| AE-father-benign-process | dc-000201-68a1ce66d8 | memory | 0.6000 | artifact_class, source_type, attck |
| AE-father-cleanup-deleted-marker | dc-000000-a91c10a774 | disk | 0.6000 | artifact_class, source_type, attck |
| AE-father-shell-log | dc-000003-3bfcdeed09 | disk | 0.6000 | artifact_class, source_type, attck |

## Unmatched Candidate Claims

- Total: 195

| rule | artifact class | count |
|---|---|---:|
| flab.filesystem.deleted_artifact_cleanup | deleted_file_candidate | 2 |
| flab.filesystem.ld_preload_configuration | preload_configuration | 63 |
| flab.filesystem.suspicious_temp_path | file | 85 |
| flab.filesystem.userland_persistence | file | 3 |
| flab.filesystem.userland_persistence | service_unit_file | 39 |
| flab.memory.process_socket_correlation | process_socket_correlation | 3 |

## Missed Expected Artifacts

No unmatched expected artifacts at candidate level.

## Per Source

| source | TP | FP | FN | precision | recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| disk | 8 | 26 | 0 | 0.2353 | 1.0000 | 0.3810 |
| memory | 2 | 3 | 0 | 0.4000 | 1.0000 | 0.5714 |
| timeline | 8 | 166 | 0 | 0.0460 | 1.0000 | 0.0879 |
| log | 0 | 0 | 0 | 0.0000 | 0.0000 | 0.0000 |

## Per Artifact Class

| class | TP | FP | FN | F1 |
|---|---:|---:|---:|---:|
| deleted_file_candidate | 1 | 2 | 0 | 0.5000 |
| file | 4 | 88 | 0 | 0.0833 |
| library_mapping | 1 | 0 | 0 | 1.0000 |
| preload_configuration | 1 | 63 | 0 | 0.0308 |
| process | 1 | 0 | 0 | 1.0000 |
| process_socket_correlation | 0 | 3 | 0 | 0.0000 |
| service_unit_file | 0 | 39 | 0 | 0.0000 |
| shared_object | 1 | 0 | 0 | 1.0000 |
| shell_history_log_event | 1 | 0 | 0 | 1.0000 |

## Match Detail

| relation | level | expectation | finding/claim | score | fields |
|---|---|---|---|---:|---|
| fp | none | __none__ | dc-000001-d03d7bfeda | 0.0000 |  |
| fp | none | __none__ | dc-000002-71b46c761a | 0.0000 |  |
| fp | none | __none__ | dc-000004-11401e1842 | 0.0000 |  |
| fp | none | __none__ | dc-000005-20041a570c | 0.0000 |  |
| fp | none | __none__ | dc-000006-d13ca30742 | 0.0000 |  |
| fp | none | __none__ | dc-000007-0fbd58ed17 | 0.0000 |  |
| fp | none | __none__ | dc-000008-52bb69d935 | 0.0000 |  |
| fp | none | __none__ | dc-000009-2260e65db9 | 0.0000 |  |
| fp | none | __none__ | dc-000010-fcd5a48639 | 0.0000 |  |
| fp | none | __none__ | dc-000011-c04d4a8afc | 0.0000 |  |
| fp | none | __none__ | dc-000012-4b0f0ff76f | 0.0000 |  |
| fp | none | __none__ | dc-000014-dbcb441fab | 0.0000 |  |
| fp | none | __none__ | dc-000015-40ef9d1e58 | 0.0000 |  |
| fp | none | __none__ | dc-000016-20efaae08b | 0.0000 |  |
| fp | none | __none__ | dc-000017-1f0030f1ee | 0.0000 |  |
| fp | none | __none__ | dc-000018-01e89600aa | 0.0000 |  |
| fp | none | __none__ | dc-000019-e8b463e447 | 0.0000 |  |
| fp | none | __none__ | dc-000020-cf759ff686 | 0.0000 |  |
| fp | none | __none__ | dc-000021-fb637f54a5 | 0.0000 |  |
| fp | none | __none__ | dc-000022-915911fdbd | 0.0000 |  |
| fp | none | __none__ | dc-000023-1803f7b8cd | 0.0000 |  |
| fp | none | __none__ | dc-000024-762a7446da | 0.0000 |  |
| fp | none | __none__ | dc-000025-2f9a486f42 | 0.0000 |  |
| fp | none | __none__ | dc-000026-374d7faa31 | 0.0000 |  |
| fp | none | __none__ | dc-000027-38bea7807e | 0.0000 |  |
| fp | none | __none__ | dc-000028-95197aa614 | 0.0000 |  |
| fp | none | __none__ | dc-000029-60c7e0315e | 0.0000 |  |
| fp | none | __none__ | dc-000030-2f26fd79ad | 0.0000 |  |
| fp | none | __none__ | dc-000031-85e07c85f6 | 0.0000 |  |
| fp | none | __none__ | dc-000033-afe3c5afd2 | 0.0000 |  |
| fp | none | __none__ | dc-000034-3f8ee603a6 | 0.0000 |  |
| fp | none | __none__ | dc-000035-04f680a0c1 | 0.0000 |  |
| fp | none | __none__ | dc-000036-0895bef79f | 0.0000 |  |
| fp | none | __none__ | dc-000037-7fa58bf61e | 0.0000 |  |
| fp | none | __none__ | dc-000038-6f80d17f6d | 0.0000 |  |
| fp | none | __none__ | dc-000039-ce083bfd6f | 0.0000 |  |
| fp | none | __none__ | dc-000040-debaa738d1 | 0.0000 |  |
| fp | none | __none__ | dc-000041-198ee1721a | 0.0000 |  |
| fp | none | __none__ | dc-000042-9fb55137b6 | 0.0000 |  |
| fp | none | __none__ | dc-000043-c7a8a5e651 | 0.0000 |  |
| fp | none | __none__ | dc-000044-3d88258cff | 0.0000 |  |
| fp | none | __none__ | dc-000045-58b92ef80d | 0.0000 |  |
| fp | none | __none__ | dc-000046-6470c28af0 | 0.0000 |  |
| fp | none | __none__ | dc-000047-5d797cf5e5 | 0.0000 |  |
| fp | none | __none__ | dc-000048-f7b9a576d0 | 0.0000 |  |
| fp | none | __none__ | dc-000049-b4e80f286c | 0.0000 |  |
| fp | none | __none__ | dc-000050-44276e2c6d | 0.0000 |  |
| fp | none | __none__ | dc-000051-20c46cb119 | 0.0000 |  |
| fp | none | __none__ | dc-000052-d438761465 | 0.0000 |  |
| fp | none | __none__ | dc-000053-4d9e987336 | 0.0000 |  |
| fp | none | __none__ | dc-000054-11edf309a7 | 0.0000 |  |
| fp | none | __none__ | dc-000055-234d02bb26 | 0.0000 |  |
| fp | none | __none__ | dc-000056-b57b0692dd | 0.0000 |  |
| fp | none | __none__ | dc-000058-0b6499e5c6 | 0.0000 |  |
| fp | none | __none__ | dc-000059-96dfa7a939 | 0.0000 |  |
| fp | none | __none__ | dc-000060-f05cb19096 | 0.0000 |  |
| fp | none | __none__ | dc-000061-a4508cdf38 | 0.0000 |  |
| fp | none | __none__ | dc-000063-17ce2977a9 | 0.0000 |  |
| fp | none | __none__ | dc-000064-e74fb7ff99 | 0.0000 |  |
| fp | none | __none__ | dc-000065-05e56f1513 | 0.0000 |  |
| fp | none | __none__ | dc-000066-c188d83c4f | 0.0000 |  |
| fp | none | __none__ | dc-000068-d7f066cbbe | 0.0000 |  |
| fp | none | __none__ | dc-000069-22ed1ed151 | 0.0000 |  |
| fp | none | __none__ | dc-000070-29cad8eaeb | 0.0000 |  |
| fp | none | __none__ | dc-000071-37449be19d | 0.0000 |  |
| fp | none | __none__ | dc-000073-45a727a2a3 | 0.0000 |  |
| fp | none | __none__ | dc-000074-b8af2e4f14 | 0.0000 |  |
| fp | none | __none__ | dc-000075-b8fc49a2eb | 0.0000 |  |
| fp | none | __none__ | dc-000076-7cb1aa7eb9 | 0.0000 |  |
| fp | none | __none__ | dc-000077-57ed39fcf9 | 0.0000 |  |
| fp | none | __none__ | dc-000078-16d2198db5 | 0.0000 |  |
| fp | none | __none__ | dc-000079-3c2976f2ba | 0.0000 |  |
| fp | none | __none__ | dc-000080-2a177d885f | 0.0000 |  |
| fp | none | __none__ | dc-000081-c7d7448ae5 | 0.0000 |  |
| fp | none | __none__ | dc-000082-85ed430624 | 0.0000 |  |
| fp | none | __none__ | dc-000083-13628e013e | 0.0000 |  |
| fp | none | __none__ | dc-000084-293be0dfeb | 0.0000 |  |
| fp | none | __none__ | dc-000085-77c236334b | 0.0000 |  |
| fp | none | __none__ | dc-000086-3ff4f0aec0 | 0.0000 |  |
| fp | none | __none__ | dc-000087-2261b5d6a0 | 0.0000 |  |
| fp | none | __none__ | dc-000088-4d69093241 | 0.0000 |  |
| fp | none | __none__ | dc-000089-e83f197352 | 0.0000 |  |
| fp | none | __none__ | dc-000090-1df502f146 | 0.0000 |  |
| fp | none | __none__ | dc-000091-a4da6c4589 | 0.0000 |  |
| fp | none | __none__ | dc-000092-7a59745e6a | 0.0000 |  |
| fp | none | __none__ | dc-000093-ec5702036a | 0.0000 |  |
| fp | none | __none__ | dc-000094-bf7977f9aa | 0.0000 |  |
| fp | none | __none__ | dc-000095-7cac240237 | 0.0000 |  |
| fp | none | __none__ | dc-000096-1501c0cc3e | 0.0000 |  |
| fp | none | __none__ | dc-000097-017d39cada | 0.0000 |  |
| fp | none | __none__ | dc-000098-bbbe28c7b6 | 0.0000 |  |
| fp | none | __none__ | dc-000099-cb6d7d984d | 0.0000 |  |
| fp | none | __none__ | dc-000100-2b5bb7c990 | 0.0000 |  |
| fp | none | __none__ | dc-000101-a8598a7715 | 0.0000 |  |
| fp | none | __none__ | dc-000102-8b5da51bef | 0.0000 |  |
| fp | none | __none__ | dc-000103-99938fd595 | 0.0000 |  |
| fp | none | __none__ | dc-000104-0ab02f4f48 | 0.0000 |  |
| fp | none | __none__ | dc-000105-f353ee7685 | 0.0000 |  |
| fp | none | __none__ | dc-000106-78cc34469d | 0.0000 |  |
| fp | none | __none__ | dc-000107-abbe6a0ed0 | 0.0000 |  |
| fp | none | __none__ | dc-000108-e77f5e1a6e | 0.0000 |  |
| fp | none | __none__ | dc-000109-b6f61811fa | 0.0000 |  |
| fp | none | __none__ | dc-000110-33d65f9cd1 | 0.0000 |  |
| fp | none | __none__ | dc-000111-1b6b5660be | 0.0000 |  |
| fp | none | __none__ | dc-000112-bc23c46350 | 0.0000 |  |
| fp | none | __none__ | dc-000113-306c53f399 | 0.0000 |  |
| fp | none | __none__ | dc-000114-796edc8efb | 0.0000 |  |
| fp | none | __none__ | dc-000115-6abc35e7be | 0.0000 |  |
| fp | none | __none__ | dc-000116-b97468d0a1 | 0.0000 |  |
| fp | none | __none__ | dc-000117-d8da20adc6 | 0.0000 |  |
| fp | none | __none__ | dc-000118-3ab1cca7bc | 0.0000 |  |
| fp | none | __none__ | dc-000119-614fb5d04e | 0.0000 |  |
| fp | none | __none__ | dc-000120-656b52bf18 | 0.0000 |  |
| fp | none | __none__ | dc-000121-4eafc9c13e | 0.0000 |  |
| fp | none | __none__ | dc-000122-ce34920cad | 0.0000 |  |
| fp | none | __none__ | dc-000123-46fb9e0a09 | 0.0000 |  |
| fp | none | __none__ | dc-000124-a780db16fa | 0.0000 |  |
| fp | none | __none__ | dc-000125-c47edf428e | 0.0000 |  |
| fp | none | __none__ | dc-000126-41d8e0863a | 0.0000 |  |
| fp | none | __none__ | dc-000127-8032c98cba | 0.0000 |  |
| fp | none | __none__ | dc-000128-4fb407f6ec | 0.0000 |  |
| fp | none | __none__ | dc-000129-ff3e52ce97 | 0.0000 |  |
| fp | none | __none__ | dc-000130-636f01d943 | 0.0000 |  |
| fp | none | __none__ | dc-000131-9743c2af02 | 0.0000 |  |
| fp | none | __none__ | dc-000132-7ac279cd8c | 0.0000 |  |
| fp | none | __none__ | dc-000133-6dfbce2022 | 0.0000 |  |
| fp | none | __none__ | dc-000134-7f2fa6963b | 0.0000 |  |
| fp | none | __none__ | dc-000135-ecd6f5314d | 0.0000 |  |
| fp | none | __none__ | dc-000136-169bb1d55e | 0.0000 |  |
| fp | none | __none__ | dc-000137-a12ef9fa71 | 0.0000 |  |
| fp | none | __none__ | dc-000138-031df191e8 | 0.0000 |  |
| fp | none | __none__ | dc-000139-1d84c91f4d | 0.0000 |  |
| fp | none | __none__ | dc-000140-c0ab7249e5 | 0.0000 |  |
| fp | none | __none__ | dc-000141-ebf4e4fc77 | 0.0000 |  |
| fp | none | __none__ | dc-000142-90b035e73d | 0.0000 |  |
| fp | none | __none__ | dc-000143-3ce6d7e115 | 0.0000 |  |
| fp | none | __none__ | dc-000144-26f5bc0259 | 0.0000 |  |
| fp | none | __none__ | dc-000145-ced2c1fc8a | 0.0000 |  |
| fp | none | __none__ | dc-000146-1a458f0806 | 0.0000 |  |
| fp | none | __none__ | dc-000147-abb5e95ad5 | 0.0000 |  |
| fp | none | __none__ | dc-000148-598a95e5fe | 0.0000 |  |
| fp | none | __none__ | dc-000149-1675e92acd | 0.0000 |  |
| fp | none | __none__ | dc-000150-ff45c5ffdb | 0.0000 |  |
| fp | none | __none__ | dc-000151-75e36b62cb | 0.0000 |  |
| fp | none | __none__ | dc-000152-4bb6b6f77a | 0.0000 |  |
| fp | none | __none__ | dc-000153-67cb2c2384 | 0.0000 |  |
| fp | none | __none__ | dc-000154-f1f0db4482 | 0.0000 |  |
| fp | none | __none__ | dc-000155-5f58b88522 | 0.0000 |  |
| fp | none | __none__ | dc-000156-9de1f77dc9 | 0.0000 |  |
| fp | none | __none__ | dc-000157-d01929f557 | 0.0000 |  |
| fp | none | __none__ | dc-000158-f2c6e53402 | 0.0000 |  |
| fp | none | __none__ | dc-000159-81b2e640f5 | 0.0000 |  |
| fp | none | __none__ | dc-000160-2e9c39e969 | 0.0000 |  |
| fp | none | __none__ | dc-000161-598a0c2033 | 0.0000 |  |
| fp | none | __none__ | dc-000162-57add69d10 | 0.0000 |  |
| fp | none | __none__ | dc-000163-daff3015cb | 0.0000 |  |
| fp | none | __none__ | dc-000164-a9ce8fcf09 | 0.0000 |  |
| fp | none | __none__ | dc-000165-6504e11453 | 0.0000 |  |
| fp | none | __none__ | dc-000166-c372677d04 | 0.0000 |  |
| fp | none | __none__ | dc-000167-5f918e50f2 | 0.0000 |  |
| fp | none | __none__ | dc-000168-9af8e0c298 | 0.0000 |  |
| fp | none | __none__ | dc-000169-06dc7373bc | 0.0000 |  |
| fp | none | __none__ | dc-000170-e45acd738b | 0.0000 |  |
| fp | none | __none__ | dc-000171-d79c2b2d9d | 0.0000 |  |
| fp | none | __none__ | dc-000172-3437f1360c | 0.0000 |  |
| fp | none | __none__ | dc-000173-bad2e2a3d9 | 0.0000 |  |
| fp | none | __none__ | dc-000174-10c201c0e4 | 0.0000 |  |
| fp | none | __none__ | dc-000175-4e4dec5906 | 0.0000 |  |
| fp | none | __none__ | dc-000176-8be320a770 | 0.0000 |  |
| fp | none | __none__ | dc-000177-129aef6b6d | 0.0000 |  |
| fp | none | __none__ | dc-000178-97cd47ee27 | 0.0000 |  |
| fp | none | __none__ | dc-000179-d8b90086c5 | 0.0000 |  |
| fp | none | __none__ | dc-000180-e981318ed1 | 0.0000 |  |
| fp | none | __none__ | dc-000181-5d282b6134 | 0.0000 |  |
| fp | none | __none__ | dc-000182-2dfa427d29 | 0.0000 |  |
| fp | none | __none__ | dc-000183-c699f1053d | 0.0000 |  |
| fp | none | __none__ | dc-000184-2bc3ec69cf | 0.0000 |  |
| fp | none | __none__ | dc-000185-a1514d3941 | 0.0000 |  |
| fp | none | __none__ | dc-000186-94b3a39fef | 0.0000 |  |
| fp | none | __none__ | dc-000187-0b13247c9c | 0.0000 |  |
| fp | none | __none__ | dc-000188-f62873b43a | 0.0000 |  |
| fp | none | __none__ | dc-000189-d2a0f9f780 | 0.0000 |  |
| fp | none | __none__ | dc-000190-413ed9c8e4 | 0.0000 |  |
| fp | none | __none__ | dc-000191-276bf5df65 | 0.0000 |  |
| fp | none | __none__ | dc-000192-d9cd813fa2 | 0.0000 |  |
| fp | none | __none__ | dc-000193-9bbbbffc5d | 0.0000 |  |
| fp | none | __none__ | dc-000194-3e41d1ec1d | 0.0000 |  |
| fp | none | __none__ | dc-000195-1b9de2843c | 0.0000 |  |
| fp | none | __none__ | dc-000196-75a78031c7 | 0.0000 |  |
| fp | none | __none__ | dc-000197-1cae1a39c9 | 0.0000 |  |
| fp | none | __none__ | dc-000198-e7d3b5fd9e | 0.0000 |  |
| fp | none | __none__ | dc-000199-bc8e1a9f27 | 0.0000 |  |
| fp | none | __none__ | dc-000202-3cda464a20 | 0.0000 |  |
| fp | none | __none__ | dc-000203-76bb5e6035 | 0.0000 |  |
| fp | none | __none__ | dc-000204-c5afff8937 | 0.0000 |  |
| tp | class | AE-father-benign-process | dc-000201-68a1ce66d8 | 0.6000 | artifact_class, source_type, attck |
| tp | class | AE-father-cleanup-deleted-marker | dc-000000-a91c10a774 | 0.6000 | artifact_class, source_type, attck |
| tp | instance | AE-father-hiding-marker | dc-000032-2e468c3d24 | 0.8500 | artifact_class, source_type, attck, path |
| tp | instance | AE-father-library-mapping | dc-000200-51b40618c7 | 0.8500 | artifact_class, source_type, attck, path |
| tp | instance | AE-father-preload-config | dc-000013-52e687fe81 | 0.8500 | artifact_class, source_type, attck, path |
| tp | instance | AE-father-shared-object | dc-000072-d70bac66ab | 0.8500 | artifact_class, source_type, attck, path |
| tp | class | AE-father-shell-log | dc-000003-3bfcdeed09 | 0.6000 | artifact_class, source_type, attck |
| tp | instance | AE-father-source-file | dc-000062-7dfda83cb5 | 0.8500 | artifact_class, source_type, attck, path |
| tp | instance | AE-father-source-metadata | dc-000067-347c378996 | 0.8500 | artifact_class, source_type, attck, path |
| tp | instance | AE-father-upstream-archive | dc-000057-ad33a78d3c | 0.8500 | artifact_class, source_type, attck, path |
