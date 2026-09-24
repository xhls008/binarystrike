# V1 Skill Import Policy

The V1 skill tree is a generated corpus (7,658 `SKILL.md` files at the
migration baseline `849be90339b0a2a...`). It is not copied wholesale into the
OpenCode V2 tree. Bulk copying would import stale instructions, duplicate
OpenCode skills, and active post-exploitation procedures without a V2
permission boundary.

## Source and destination

- Source snapshot: `/home/flybear/flybear_data/llm_tools/binarystrike/.binarystrike/skill`
- V2 destination: `/home/flybear/flybear_data/llm_tools/binarystrike-v2/.opencode/skills`
- OpenCode V2 reference: `/home/flybear/flybear_data/llm_tools/ref/opencode-v2-source`

## Import rule

Only a reviewed skill is imported when all of the following are true:

1. Its name and purpose are listed in `V1_V2_CAPABILITY_MATRIX.md` or an
   approved follow-up change.
2. Its instructions are rewritten or reviewed for the V2 project boundary;
   copying a V1 file verbatim is not an import.
3. Active network or host operations identify `scope_check`, the required V2
   permission, and the passive evidence path (`record_http_observation`,
   `record_browser_observation`, or a blackboard Fact).
4. Unverified output remains a Hint and proposed verification is an Intent;
   the skill cannot silently approve a Finding.
5. A parseability/permission test is added under `packages/binarystrike/test`.

The current reviewed set is the nine web/recon skills plus the blackboard,
browser-observation, cloud-readonly-planning, platform-readonly-planning,
dynamic-debugging, DecompileAI Lite, and Bun file-I/O skills in
`.opencode/skills/`. Generic OpenCode skills remain owned by the V2 reference
tree and are not duplicated.

## Explicit exclusions

The generated MITRE/framework index and V1 host hooks that capture credentials,
keys, memory, keystrokes, TLS plaintext, or bypass security controls remain
source-only. Their safe V2 replacement is a read-only planning boundary where
one exists (`cloud_plan` and `platform_plan`); no V1 server, database, session,
or global registry is imported.
