# Scenario report: scenario_01_ldpreload (ubuntu-22.04_scenario_01_ldpreload_20260614-115809)

- distro: `ubuntu-22.04`  cleanup: `False`
- ruleset_hash: `sha256:b5ea64992d4cd9f7c41d9060ed61066e5b688f5488856f4b946eaaaa6f844e31`
- contributing tools: `plaso|tsk|vol3`

## Metrics

| metric | value | raw |
| --- | --- | --- |
| recall | 1.000 | 6/6 events |
| precision | 0.667 | 8/12 claims |
| f1 | 0.800 | - |
| order_pairwise | 1.000 | - |
| kendall_tau | 0.913 | - |
| time_mae_s | 1.292 | - |
| f1 * order_pairwise (DERIVED) | 0.800 | f1=0.800 x order=1.000 |

## Recall by rule layer

- community only: 1.000
- community + custom: 1.000

## Unique tool contribution (TP events found by exactly one tool)

- tsk: 3
- plaso: 0
- vol3: 1

## Per-event coverage (was each step found, by which tool)

| gt_id | technique | event_class | tsk | plaso | vol3 | delta_t_s |
| --- | --- | --- | --- | --- | --- | --- |
| G1 | T1082 | file_created | x | - | - | 1.486 |
| G2 | T1574.006 | persistence_installed | x | x | - | 0.618 |
| G3 | T1574.006 | file_created | x | - | - | 1.418 |
| G4 | T1574.006 | process_exec | - | - | x | n/a |
| G5 | T1059.004 | network_connection | - | x | x | n/a |
| G6 | T1059.004 | file_created | x | - | - | 1.647 |

## True positives

| gt_id | tools | delta_t_s | primary raw_ref |
| --- | --- | --- | --- |
| G1 | tsk | 1.486 | `bodyfile:inode=1480` |
| G2 | plaso|tsk | 0.618 | `plaso:event:14326` |
| G3 | tsk | 1.418 | `bodyfile:inode=1487` |
| G4 | vol3 | n/a | `vol3:linux.proc.Maps:pid=761` |
| G5 | plaso|vol3 | n/a | `vol3:linux.sockstat:pid=769` |
| G6 | tsk | 1.647 | `bodyfile:inode=1483` |

## False positives

| cluster_id | representative raw_ref |
| --- | --- |
| c-001 | `plaso:event:14288` |
| c-005 | `bodyfile:inode=258154` |
| c-007 | `plaso:event:14332` |
| c-009 | `vol3:linux.malfind:pid=295:start=140288958685184` |

## False negatives

- (none)
