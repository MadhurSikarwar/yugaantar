import { useState } from "react";
import { decide, policyRules } from "../lib/policy.ts";

const owners = { brief: "maya", ledger: "noor" };

function Choice({
  legend,
  options,
  value,
  onChange,
}: {
  legend: string;
  options: string[];
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <fieldset className="choice">
      <legend>{legend}</legend>
      {options.map((option) => (
        <label key={option}>
          <input
            type="radio"
            name={legend}
            checked={value === option}
            onChange={() => onChange(option)}
          />
          <span>{option}</span>
        </label>
      ))}
    </fieldset>
  );
}

export default function PolicyLab() {
  const [actor, setActor] = useState("maya");
  const [asset, setAsset] = useState("brief");
  const [revoked, setRevoked] = useState(false);
  const [disabled, setDisabled] = useState(false);
  const result = decide({ actor, asset, revoked, disabled, owners });
  return (
    <section className="lab policy" id="policy" aria-labelledby="policy-title">
      <header className="lab-intro">
        <h2 id="policy-title">How a read request is decided</h2>
        <p>
          Five rules are checked in order and the first match decides. Maya owns
          the brief and Noor owns the ledger.
        </p>
      </header>
      <div className="policy-body">
        <div className="policy-form">
          <Choice
            legend="Who asks"
            options={["maya", "noor", "eve"]}
            value={actor}
            onChange={setActor}
          />
          <Choice
            legend="Which file"
            options={["brief", "ledger", "payroll"]}
            value={asset}
            onChange={setAsset}
          />
          <fieldset className="choice">
            <legend>Status of {actor}</legend>
            <label>
              <input
                type="checkbox"
                checked={revoked}
                onChange={(e) => setRevoked(e.target.checked)}
              />
              <span>Revoked</span>
            </label>
            <label>
              <input
                type="checkbox"
                checked={disabled}
                onChange={(e) => setDisabled(e.target.checked)}
              />
              <span>Disabled</span>
            </label>
          </fieldset>
        </div>
        <ol className="rules">
          {policyRules.map((rule, i) => (
            <li
              key={rule.id}
              className={
                i < result.index
                  ? "passed"
                  : i === result.index
                    ? `matched ${rule.allow ? "allow" : "deny"}`
                    : "unreached"
              }
              aria-current={i === result.index ? "true" : undefined}
            >
              <span className="rule-when">{rule.when}</span>
              <code>{rule.id}</code>
              <span className="rule-state">
                {i < result.index
                  ? "No"
                  : i === result.index
                    ? rule.allow
                      ? "Allow"
                      : "Deny"
                    : "Not reached"}
              </span>
            </li>
          ))}
        </ol>
        <div className="replies" aria-live="polite">
          <div>
            <h3>The caller receives</h3>
            <code>
              {result.allow
                ? '{"decision": "allow", "body": "…"}'
                : '{"decision": "deny"}'}
            </code>
          </div>
          <div>
            <h3>The audit log records</h3>
            <code>
              {actor} read {asset}: {result.allow ? "allow" : "deny"},{" "}
              {result.id}
            </code>
          </div>
        </div>
      </div>
    </section>
  );
}
