export type Provider = "aws" | "azure" | "kubernetes"

export type Step = {
  id: string
  title: string
  purpose: string
  command: string
  read_only: true
  evidence: string
}

export type Plan = {
  provider: Provider
  scope: string
  prerequisites: string[]
  steps: Step[]
  safety: string[]
}

type Catalog = Omit<Plan, "provider" | "scope" | "steps"> & { steps: Step[] }

const catalogs: Record<Provider, Catalog> = {
  aws: {
    prerequisites: ["Use an explicitly authorized account and profile.", "Set AWS_REGION or pass a region to the operator."],
    safety: [
      "This tool only returns a plan; it never invokes the AWS CLI or SDK.",
      "Prefer metadata/list operations first and redact account, token, and secret values before recording facts.",
      "Record each command result as a Fact and unresolved leads as a Hint before proposing an Intent.",
    ],
    steps: [
      {
        id: "identity",
        title: "Confirm caller identity",
        purpose: "Bind observations to the authorized account and principal.",
        command: "aws sts get-caller-identity --output json",
        read_only: true,
        evidence: "account, ARN, and user ID (redact session details)",
      },
      {
        id: "iam",
        title: "Inspect effective IAM surface",
        purpose: "Identify attached policy metadata and possible privilege boundaries without changing IAM.",
        command: "aws iam list-users --output json && aws iam list-roles --output json",
        read_only: true,
        evidence: "principal and role metadata, policy names, and trust relationships",
      },
      {
        id: "storage",
        title: "Inventory storage metadata",
        purpose: "Map buckets and regions before any object access is considered.",
        command: "aws s3api list-buckets --output json",
        read_only: true,
        evidence: "bucket names, regions, and public-access configuration where authorized",
      },
      {
        id: "secrets",
        title: "Inventory secret stores",
        purpose: "Find secret stores without retrieving secret values.",
        command: "aws secretsmanager list-secrets --include-planned-deletion --output json",
        read_only: true,
        evidence: "secret identifiers, tags, rotation metadata, and owning account",
      },
      {
        id: "logging",
        title: "Check CloudTrail posture",
        purpose: "Establish whether management activity is being logged before testing.",
        command: "aws cloudtrail describe-trails --include-shadow-trails --output json",
        read_only: true,
        evidence: "trail names, regions, multi-region status, and log destinations",
      },
    ],
  },
  azure: {
    prerequisites: ["Use an explicitly authorized tenant and subscription.", "Authenticate with az login or a scoped workload identity."],
    safety: [
      "This tool only returns a plan; it never invokes Azure CLI or Graph APIs.",
      "Do not fetch Key Vault values or tokens as part of inventory; retain metadata only.",
      "Keep tenant, subscription, and principal identifiers in Fact provenance when recording results.",
    ],
    steps: [
      {
        id: "identity",
        title: "Confirm Azure identity",
        purpose: "Bind observations to the authorized tenant, subscription, and principal.",
        command: "az account show --output json",
        read_only: true,
        evidence: "tenant, subscription, user, and environment identifiers",
      },
      {
        id: "roles",
        title: "Inspect role assignments",
        purpose: "Map effective RBAC assignments without granting or modifying roles.",
        command: "az role assignment list --all --include-inherited --output json",
        read_only: true,
        evidence: "principal, scope, role definition, and inheritance metadata",
      },
      {
        id: "resources",
        title: "Inventory resources",
        purpose: "Build a subscription resource map for later, bounded analysis.",
        command: "az resource list --output json",
        read_only: true,
        evidence: "resource IDs, types, locations, tags, and resource groups",
      },
      {
        id: "vaults",
        title: "Inventory Key Vault metadata",
        purpose: "Identify vault exposure and access-policy posture without reading values.",
        command: "az keyvault list --output json",
        read_only: true,
        evidence: "vault IDs, locations, tenant IDs, and enabled service flags",
      },
      {
        id: "activity",
        title: "Review activity logging",
        purpose: "Establish the observable control-plane history for the assessment window.",
        command: "az monitor activity-log list --max-events 50 --output json",
        read_only: true,
        evidence: "event timestamps, callers, operations, scopes, and outcomes",
      },
    ],
  },
  kubernetes: {
    prerequisites: ["Use a kubeconfig and cluster context explicitly authorized for assessment.", "Confirm the current context before collecting metadata."],
    safety: [
      "This tool only returns a plan; it never invokes kubectl or Kubernetes APIs.",
      "Inventory metadata only: do not read Secret data, exec into pods, or create resources in this plan.",
      "Record authorization failures as Facts; do not retry with broader credentials without an explicit Intent.",
    ],
    steps: [
      {
        id: "context",
        title: "Confirm cluster context",
        purpose: "Bind observations to the authorized cluster and current user.",
        command: "kubectl config current-context && kubectl cluster-info",
        read_only: true,
        evidence: "context name, API endpoint, and reachability status",
      },
      {
        id: "authorization",
        title: "Inspect effective permissions",
        purpose: "Understand the current subject's permissions without changing RBAC.",
        command: "kubectl auth can-i --list",
        read_only: true,
        evidence: "resource, verb, namespace, and non-resource URL permissions",
      },
      {
        id: "workloads",
        title: "Inventory workload metadata",
        purpose: "Map namespaces, pods, services, and ingress without reading mounted data.",
        command: "kubectl get namespaces,pods,services,ingress --all-namespaces -o json",
        read_only: true,
        evidence: "names, labels, images, service ports, ingress hosts, and status",
      },
      {
        id: "rbac",
        title: "Inventory RBAC bindings",
        purpose: "Identify role and binding relationships for bounded authorization review.",
        command: "kubectl get roles,clusterroles,rolebindings,clusterrolebindings --all-namespaces -o json",
        read_only: true,
        evidence: "subjects, role references, namespaces, and aggregation labels",
      },
      {
        id: "network",
        title: "Inventory network and pod-security controls",
        purpose: "Map network policies and security context metadata without probing workloads.",
        command: "kubectl get networkpolicies,podsecurityadmissionconfigurations --all-namespaces -o json",
        read_only: true,
        evidence: "selectors, ingress/egress rules, and enforcement labels",
      },
    ],
  },
}

function clean(value: string | undefined, fallback: string) {
  const result = value?.trim()
  return result || fallback
}

export namespace CloudPlan {
  export function plan(input: { provider: Provider; scope?: string; focus?: string }) {
    const catalog = catalogs[input.provider]
    const focus = input.focus?.trim().toLowerCase()
    const steps = focus
      ? catalog.steps.filter((step) => step.id === focus || step.title.toLowerCase().includes(focus))
      : catalog.steps
    if (!steps.length) throw new Error(`Unknown ${input.provider} cloud planning focus: ${input.focus}`)
    return {
      provider: input.provider,
      scope: clean(input.scope, "authorized assessment scope (declare before execution)"),
      prerequisites: [...catalog.prerequisites],
      steps: steps.map((step) => ({ ...step })),
      safety: [...catalog.safety],
    } satisfies Plan
  }
}
