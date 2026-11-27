/** Browser mirror of t4/policy.py: one ordered list of rules, first match wins. */
export const policyRules = [
  { id: "POL-REVOKED", when: "The actor was revoked", allow: false },
  { id: "POL-DISABLED", when: "The actor was disabled at setup", allow: false },
  { id: "POL-UNKNOWN-ASSET", when: "The file does not exist", allow: false },
  {
    id: "POL-NOT-OWNER",
    when: "The actor does not own the file",
    allow: false,
  },
  { id: "POL-ALLOW-OWNER", when: "The actor owns the file", allow: true },
] as const;

export interface PolicyInput {
  actor: string;
  asset: string;
  revoked: boolean;
  disabled: boolean;
  owners: Record<string, string>;
}

export function decide(input: PolicyInput) {
  const owner = Object.hasOwn(input.owners, input.asset)
    ? input.owners[input.asset]
    : undefined;
  const index = input.revoked
    ? 0
    : input.disabled
      ? 1
      : owner === undefined
        ? 2
        : owner !== input.actor
          ? 3
          : 4;
  return { index, ...policyRules[index] };
}
