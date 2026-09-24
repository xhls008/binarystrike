---
name: cloud-readonly-planning
description: Plan authorized AWS, Azure, and Kubernetes inventory without executing cloud or cluster operations
category: cloud-security
version: "1.0"
---

# Cloud Read-only Planning

Use `cloud_plan` to produce a provider-specific inventory and authorization
plan. The tool is deliberately a planning boundary: it does not invoke `aws`,
`az`, `kubectl`, cloud SDKs, metadata endpoints, or cluster APIs.

## Provider scope

- `aws`: caller identity, IAM metadata, storage inventory, secret-store
  metadata, and CloudTrail posture.
- `azure`: account identity, RBAC assignments, resource inventory, Key Vault
  metadata, and activity-log posture.
- `kubernetes`: context, `auth can-i`, workload metadata, RBAC bindings, and
  network/pod-security metadata.

Declare the authorized account, tenant/subscription, or cluster in `scope`.
Use `focus` to request one plan step when a narrower review is appropriate.

## Blackboard coordination

Record command results as sourced **Facts**, unresolved exposure leads as
**Hints**, and bounded follow-up validation as **Intents**. Do not read secret
values, exec into pods, create resources, modify IAM/RBAC, disable logging, or
access instance metadata from this read-only planning skill. Any active action
requires a separate explicit scope check and permissioned tool.
