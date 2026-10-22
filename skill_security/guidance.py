"""Reviewed explanations for normalized rules, independent of scan decisions.

These are review prompts, not confirmed vulnerabilities or automatic fixes.
Only exact, vendor-scoped identifiers select text. Scanner prose, snippets,
paths, and URLs are never used. New or changed rules require human review; no
prefix matching, suppression, severity change, or coverage override occurs.

NVIDIA definitions reviewed at 091a509b3d6ba8ff5be528966e1f43c2e68cf214:
  src/skillspector/nodes/analyzers/pattern_defaults.py
  src/skillspector/nodes/analyzers/mcp_rug_pull.py (RP1 has two meanings)
  src/skillspector/nodes/finalize_inspection_ledger.py (AE1 is a coverage gap)
Cisco definitions reviewed at a24df340ca6056a6446a239f4a7b114b11c6073a:
  skill_scanner/data/packs/core/signatures/*.yaml
The references preserve that reviewed meaning even when vendors release a new
version. Consult the engine pin in the report when checking later definitions.
"""

from __future__ import annotations


_NVIDIA = "https://github.com/NVIDIA/SkillSpector/blob/091a509b3d6ba8ff5be528966e1f43c2e68cf214/"
_CISCO = "https://github.com/cisco-ai-defense/skill-scanner/blob/a24df340ca6056a6446a239f4a7b114b11c6073a/"
_NVIDIA_PATTERNS = _NVIDIA + "src/skillspector/nodes/analyzers/pattern_defaults.py"
_CISCO_RULES = _CISCO + "skill_scanner/data/packs/core/signatures/"


def _entry(title: str, why: str, recommendation: str, reference: str) -> dict[str, str]:
    return {
        "title": title,
        "why": why,
        "recommendation": recommendation,
        "reference": reference,
        "specificity": "reviewed-rule",
    }


_NVIDIA_GUIDANCE = {
    "LP3": _entry(
        "Review undeclared tool scope",
        "The scanner detected capabilities without a tool-scope declaration it recognizes. This does not by itself prove unauthorized behavior.",
        "Compare the detected operations with the intended host and authorized task. Restrict unnecessary capabilities and, where the host supports it, declare only the required allowed-tools or permissions. A declaration alone does not enforce access controls.",
        _NVIDIA_PATTERNS,
    ),
    "AE1": _entry(
        "Resolve an uninspected reference",
        "A referenced artifact was not completely inspected. This finding identifies missing analysis evidence; it does not establish that the artifact is malicious.",
        "Review the reference and the report's coverage reasons. Include any required local dependency in the submitted package, correct broken references, or arrange separate inspection of unsupported material. Rerun after resolving the coverage gap; do not treat missing evidence as a pass.",
        _NVIDIA + "src/skillspector/nodes/finalize_inspection_ledger.py",
    ),
    "EA2": _entry(
        "Review autonomy for high-impact actions",
        "The rule flags instructions that may allow consequential actions without an adequate human decision point.",
        "Identify destructive, irreversible, financial, or externally visible operations. Bound their scope and require appropriate explicit authorization before execution; document stop conditions and recovery steps.",
        _NVIDIA_PATTERNS,
    ),
    "AST4": _entry(
        "Review external command execution",
        "The scanner found a subprocess call. A call alone is not proof of injection; risk depends on executable selection, arguments, and untrusted input.",
        "Use an explicit argument list with shell=False, validate executable and argument choices, and keep untrusted values from becoming commands or options. Restrict working directories and execution privileges, then test hostile inputs.",
        _NVIDIA_PATTERNS,
    ),
    "EA3": _entry(
        "Review actions beyond the declared purpose",
        "The rule flags possible expansion of a skill's behavior beyond its stated task.",
        "Trace the flagged instructions to the user-authorized outcome. Remove unrelated operations or separate them into an explicitly selected task with clear permission and data boundaries.",
        _NVIDIA_PATTERNS,
    ),
    "PE3": _entry(
        "Review access to credential files",
        "The rule flags references or code that may access credential-bearing files. Context determines whether access is required and authorized.",
        "Remove unnecessary credential-file reads. For required authentication, use a narrowly scoped credential interface or secret manager, avoid bulk discovery, and prevent secrets from entering logs, reports, or outbound payloads.",
        _NVIDIA_PATTERNS,
    ),
    "P1": _entry(
        "Review instruction overrides",
        "The rule flags language that may tell an agent to disregard higher-priority instructions or safety boundaries.",
        "Rewrite active directives to respect the host's instruction hierarchy and user authorization. If the text is an inert test or quotation, make that boundary explicit and ensure it cannot become executable agent instructions.",
        _NVIDIA_PATTERNS,
    ),
    "P2": _entry(
        "Inspect concealed instructions",
        "The rule flags instructions in comments or visually hidden text that may escape ordinary review.",
        "Inspect comments, invisible Unicode, and rendered versus source text. Remove concealed operational directives and make any necessary instructions visible, reviewable, and subject to the same authorization boundaries.",
        _NVIDIA_PATTERNS,
    ),
    "P6": _entry(
        "Review disclosure of protected instructions",
        "The rule flags requests to reveal system prompts or internal instructions that the skill may not be authorized to disclose.",
        "Remove requests to extract protected instructions. Provide user-facing capability documentation or explicitly public configuration instead, without copying hidden prompts or credentials.",
        _NVIDIA_PATTERNS,
    ),
    "E1": _entry(
        "Review outbound data transfers",
        "The rule flags data sent to an external destination. A network operation can be legitimate; its destination, payload, and authorization need review.",
        "Trace data from its source to the outbound request. Allow only required destinations and fields, obtain appropriate consent, and exclude unrelated private data and credentials from payloads and logs.",
        _NVIDIA_PATTERNS,
    ),
    "AS3": _entry(
        "Review access to other skills",
        "The rule flags enumeration or reading of other installed skills, which can expose instructions or data outside this package's task.",
        "Verify that cross-skill discovery is an explicit, authorized capability. Limit access to the required public metadata or named packages and remove broad reads of neighboring skill content or private runtime state.",
        _NVIDIA_PATTERNS,
    ),
    "TM1": _entry(
        "Review unsafe tool arguments",
        "The rule flags parameters that may weaken tool safeguards or broaden an operation's effect.",
        "Validate arguments against the intended operation, reject unexpected options, and use safe defaults. Bound destructive targets and require authorization for the actual effect rather than trusting a force flag or unchecked glob.",
        _NVIDIA_PATTERNS,
    ),
    "RP1": _entry(
        "Review dependency pins and permission changes",
        "This identifier covers unpinned MCP or container dependencies and, when a previous manifest is supplied, newly added permissions. The identifier alone cannot distinguish the two cases.",
        "Inspect the relevant dependency reference or manifest comparison. Pin executable dependencies to reviewed versions or immutable digests, and explicitly review newly requested permissions before accepting an update.",
        _NVIDIA + "src/skillspector/nodes/analyzers/mcp_rug_pull.py",
    ),
    "YR4": _entry(
        "Review a tool or exploit signature",
        "A YARA signature associated with offensive tooling or exploit indicators matched; this identifier also serves as a fallback for unclassified YARA matches. A match alone does not establish malicious intent.",
        "Inspect the matched file and the vendor rule at the recorded engine revision. Remove unexpected executable material. For authorized security examples, verify that fixtures are inert, clearly scoped, and cannot run during installation or normal skill use.",
        _NVIDIA + "src/skillspector/nodes/analyzers/static_yara.py",
    ),
    "AR3": _entry(
        "Review attempts to disable safeguards",
        "The rule flags language that may claim the agent's safety policies or restrictions no longer apply.",
        "Remove active instructions that nullify host safeguards. Express the permitted task and authorization boundaries directly; keep quoted adversarial examples inert and clearly separated from operational instructions.",
        _NVIDIA_PATTERNS,
    ),
}


_CISCO_GUIDANCE = {
    "COMMAND_INJECTION_EVAL": _entry(
        "Review dynamic code execution",
        "The rule flags dynamic evaluation that can turn data into executable code.",
        "Replace evaluation with a parser for the required data format or a fixed dispatch table. Do not evaluate package text, network responses, or user-controlled expressions as code.",
        _CISCO_RULES + "command_injection.yaml",
    ),
    "COMMAND_INJECTION_OS_SYSTEM": _entry(
        "Review constructed shell commands",
        "The rule flags shell execution involving constructed strings, where data may alter command syntax.",
        "Use a fixed executable and explicit argument list with shell=False. Validate values and option boundaries, and keep untrusted input out of shell command strings.",
        _CISCO_RULES + "command_injection.yaml",
    ),
    "COMMAND_INJECTION_SHELL_TRUE": _entry(
        "Review shell interpretation",
        "Enabling shell interpretation can make command strings sensitive to injected operators or substitutions.",
        "Use shell=False with an argument list where possible. If shell features are essential, isolate a fixed script from untrusted values and review every input boundary before execution.",
        _CISCO_RULES + "command_injection.yaml",
    ),
    "COMMAND_INJECTION_JS_CHILD_PROCESS": _entry(
        "Review Node.js command execution",
        "The rule flags child-process use that may allow a shell to interpret untrusted text.",
        "Prefer execFile or spawn with a fixed executable, explicit argument array, and shell disabled. Validate arguments and reject untrusted options; do not concatenate inputs into commands.",
        _CISCO_RULES + "command_injection.yaml",
    ),
    "PATH_TRAVERSAL_OPEN": _entry(
        "Review file-path containment",
        "The rule flags file access whose path may be controlled by untrusted input.",
        "Resolve the intended target against an allowed root and verify containment before access. Reject absolute paths, traversal, and symlink escapes as appropriate; test neighboring and outside-root targets.",
        _CISCO_RULES + "command_injection.yaml",
    ),
    "SQL_INJECTION_STRING_FORMAT": _entry(
        "Review SQL construction",
        "The rule flags interpolated SQL in which untrusted values may become query syntax.",
        "Bind data through the database driver's parameter API. Select identifiers and sort directions from fixed allowlists; do not rely on string escaping as a substitute for parameters.",
        _CISCO_RULES + "command_injection.yaml",
    ),
    "DATA_EXFIL_SENSITIVE_FILES": _entry(
        "Review sensitive-file reads",
        "The rule flags access to files that may contain credentials or sensitive system information.",
        "Remove unrelated reads and narrow required access to the authorized task. Use a scoped credential interface for authentication and verify that sensitive content is never copied into output or network requests.",
        _CISCO_RULES + "data_exfiltration.yaml",
    ),
    "DATA_EXFIL_ENV_VARS": _entry(
        "Review environment collection",
        "Collecting the process environment in bulk can capture credentials unrelated to the skill's purpose.",
        "Read only named variables required for the task. Remove whole-environment snapshots and prevent secret values from reaching diagnostics, generated files, or network payloads.",
        _CISCO_RULES + "data_exfiltration.yaml",
    ),
    "DATA_EXFIL_BASE64_AND_NETWORK": _entry(
        "Review encoded outbound data",
        "Encoding combined with a network operation may stage data for transfer; encoding does not provide confidentiality.",
        "Trace the decoded source data, destination, and authorization. Remove unnecessary transfers and avoid sending credentials or unrelated private information, whether encoded or plain text.",
        _CISCO_RULES + "data_exfiltration.yaml",
    ),
    "PROMPT_INJECTION_REVEAL_SYSTEM": _entry(
        "Review requests for internal instructions",
        "The rule flags language asking an agent to disclose system instructions or protected configuration.",
        "Remove requests for protected prompts or configuration. Use explicitly public capability documentation and avoid disclosing hidden instructions or authentication material.",
        _CISCO_RULES + "prompt_injection.yaml",
    ),
    "PROMPT_INJECTION_CONCEALMENT": _entry(
        "Review concealed actions",
        "The rule flags directives that may hide the skill's actions from the user.",
        "Make consequential actions and their effects visible. Remove instructions to mislead the user or hide activity, and retain appropriate authorization and reporting for external or destructive operations.",
        _CISCO_RULES + "prompt_injection.yaml",
    ),
    "TOOL_ABUSE_UNTRUSTED_PACKAGE_SOURCE": _entry(
        "Review executable dependency sources",
        "The rule flags installation from remote sources that need explicit provenance and integrity review.",
        "Use the intended publisher's verified source, pin an immutable reviewed artifact, and verify its integrity. Keep installation out of untrusted package processing and review dependency changes before use.",
        _CISCO_RULES + "unauthorized_tool_use.yaml",
    ),
}


# Explicit aliases only: a future SECRET_* or DATA_EXFIL_* rule stays unknown.
for _rule in (
    "SECRET_AWS_KEY", "SECRET_STRIPE_KEY", "SECRET_GOOGLE_API",
    "SECRET_GITHUB_TOKEN", "SECRET_JWT_TOKEN", "SECRET_PRIVATE_KEY",
    "SECRET_PASSWORD_VAR", "SECRET_CONNECTION_STRING",
):
    _CISCO_GUIDANCE[_rule] = _entry(
        "Review a possible embedded credential",
        "The rule matched a credential-like value. It may be a test placeholder, but any live credential in a package can be exposed to every recipient.",
        "Determine whether the value is real without publishing it. Revoke or rotate exposed live credentials, remove them from the distributed package, and obtain required secrets through a scoped runtime mechanism. Use clearly synthetic fixtures for examples.",
        _CISCO_RULES + "hardcoded_secrets.yaml",
    )

for _rule in (
    "DATA_EXFIL_NETWORK_REQUESTS", "DATA_EXFIL_HTTP_POST",
    "DATA_EXFIL_SOCKET_CONNECT", "DATA_EXFIL_JS_NETWORK",
):
    _CISCO_GUIDANCE[_rule] = _entry(
        "Review an outbound connection",
        "The rule flags a network operation that can send data outside the local environment. The operation alone does not establish exfiltration.",
        "Verify the destination and trace the payload back to its sources. Allow only required transfers with appropriate authorization; exclude unrelated private content and credentials from payloads and logs.",
        _CISCO_RULES + "data_exfiltration.yaml",
    )

for _rule in (
    "PROMPT_INJECTION_IGNORE_INSTRUCTIONS", "PROMPT_INJECTION_UNRESTRICTED_MODE",
    "PROMPT_INJECTION_BYPASS_POLICY",
):
    _CISCO_GUIDANCE[_rule] = _entry(
        "Review attempts to override agent boundaries",
        "The rule flags language that may override the host's instructions or bypass its safeguards.",
        "Rewrite active directives to respect the instruction hierarchy and user authorization. Keep adversarial examples or quotations clearly inert, and verify that they cannot be interpreted as instructions to the operating agent.",
        _CISCO_RULES + "prompt_injection.yaml",
    )


_GUIDANCE = {"nvidia": _NVIDIA_GUIDANCE, "cisco": _CISCO_GUIDANCE}
_REFERENCES = {
    "nvidia": "https://github.com/NVIDIA/SkillSpector",
    "cisco": "https://github.com/cisco-ai-defense/skill-scanner",
}


def guidance_for(engine: object, rule_id: object) -> dict[str, str]:
    """Return a fresh, static object; never reflect caller-controlled content."""
    known_engine = engine if type(engine) is str and engine in _GUIDANCE else None
    if known_engine and type(rule_id) is str:
        reviewed = _GUIDANCE[known_engine].get(rule_id)
        if reviewed is not None:
            return dict(reviewed)
    return {
        "title": "Rule requires vendor review",
        "why": "Shield has no reviewed explanation for this engine and rule combination. Its meaning cannot be inferred from the identifier or severity alone.",
        "recommendation": "Consult the official scanner source at the engine revision recorded in the report and inspect the relevant package content locally. Establish the rule's meaning before choosing a correction; retain the finding and any incomplete coverage until review is complete.",
        "reference": _REFERENCES.get(known_engine, "https://github.com/OKHP3/skillz-shield"),
        "specificity": "unknown-rule",
    }
