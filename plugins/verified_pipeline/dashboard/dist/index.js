(function () {
  "use strict";
  const SDK = window.__HERMES_PLUGIN_SDK__;
  const registry = window.__HERMES_PLUGINS__;
  if (!SDK || !registry) return;

  const React = SDK.React;
  const h = React.createElement;
  const hooks = SDK.hooks;
  const C = SDK.components;

  function api(path, options) {
    return SDK.fetchJSON("/api/plugins/verified-pipeline" + path, options);
  }

  function messageFromError(err) {
    const raw = err && err.message ? String(err.message) : String(err || "Request failed");
    const match = raw.match(/^\d{3}:\s*(.*)$/s);
    const body = match ? match[1] : raw;
    try {
      const parsed = JSON.parse(body);
      if (parsed && parsed.detail) {
        if (typeof parsed.detail === "string") return parsed.detail;
        if (parsed.detail.message) return parsed.detail.code + ": " + parsed.detail.message;
      }
    } catch (_) {}
    return body;
  }

  function VerifiedPipelinePage() {
    const [specificationId, setSpecificationId] = hooks.useState("");
    const [revision, setRevision] = hooks.useState("1");
    const [board, setBoard] = hooks.useState("");
    const [artifact, setArtifact] = hooks.useState("");
    const [intake, setIntake] = hooks.useState(null);
    const [reviewed, setReviewed] = hooks.useState(false);
    const [feedback, setFeedback] = hooks.useState("");
    const [result, setResult] = hooks.useState(null);
    const [busy, setBusy] = hooks.useState(false);
    const [error, setError] = hooks.useState("");

    function registerIntake(event) {
      event.preventDefault();
      setBusy(true); setError(""); setResult(null); setReviewed(false);
      api("/intakes", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          specification_id: specificationId,
          revision: Number(revision),
          artifact_text: artifact,
          board: board || null,
        }),
      }).then(function (data) {
        setIntake(data);
      }).catch(function (err) {
        setError(messageFromError(err));
      }).finally(function () { setBusy(false); });
    }

    function decide(action) {
      if (!intake || !reviewed) return;
      setBusy(true); setError("");
      const requestId = "dashboard-" + (window.crypto && window.crypto.randomUUID
        ? window.crypto.randomUUID()
        : Date.now() + "-" + Math.random().toString(16).slice(2));
      api("/intakes/" + encodeURIComponent(intake.run_id) + "/decision", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          request_id: requestId,
          action: action,
          decision_nonce: intake.decision_nonce,
          artifact_sha256: intake.artifact_sha256,
          feedback: feedback || null,
        }),
      }).then(function (data) {
        setResult(data);
      }).catch(function (err) {
        setError(messageFromError(err));
      }).finally(function () { setBusy(false); });
    }

    function reconcile() {
      if (!intake) return;
      setBusy(true); setError("");
      api("/intakes/" + encodeURIComponent(intake.run_id) + "/reconcile", {
        method: "POST",
      }).then(function (data) {
        setResult(function (prior) {
          return { decision: prior && prior.decision ? prior.decision : {}, projection: data.projection };
        });
      }).catch(function (err) {
        setError(messageFromError(err));
      }).finally(function () { setBusy(false); });
    }

    if (!intake) {
      return h("main", { className: "vp-page" },
        h("header", { className: "vp-header" },
          h("div", null,
            h("p", { className: "vp-kicker" }, "DETERMINISTIC CONNECTOR"),
            h("h1", null, "Verified Pipeline"),
            h("p", { className: "vp-subtitle" }, "Bind one human decision to exact specification bytes and create exactly one bounded task.")
          )
        ),
        error && h("div", { className: "vp-alert vp-error" }, error),
        h("form", { className: "vp-card", onSubmit: registerIntake },
          h("div", { className: "vp-grid" },
            h("label", null, "Specification ID", h("input", { required: true, value: specificationId, onChange: function (e) { setSpecificationId(e.target.value); }, placeholder: "spec-example" })),
            h("label", null, "Revision", h("input", { required: true, type: "number", min: 1, value: revision, onChange: function (e) { setRevision(e.target.value); } })),
            h("label", null, "Kanban board (optional)", h("input", { value: board, onChange: function (e) { setBoard(e.target.value); }, placeholder: "current board" }))
          ),
          h("label", { className: "vp-artifact-label" }, "Exact specification text",
            h("textarea", { required: true, value: artifact, onChange: function (e) { setArtifact(e.target.value); }, rows: 20, spellCheck: false })
          ),
          h(C.Button, { type: "submit", disabled: busy || !artifact || !specificationId }, busy ? "Registering…" : "Freeze review bytes")
        )
      );
    }

    const projection = result && result.projection;
    return h("main", { className: "vp-page" },
      h("header", { className: "vp-header" },
        h("div", null,
          h("p", { className: "vp-kicker" }, "EXACT-BYTE REVIEW"),
          h("h1", null, intake.specification_id + " · revision " + intake.revision),
          h("p", { className: "vp-subtitle" }, "The decision nonce and digest below are bound to the displayed bytes.")
        ),
        !result && h(C.Button, { variant: "outline", onClick: function () { setIntake(null); setReviewed(false); setError(""); } }, "Start over")
      ),
      error && h("div", { className: "vp-alert vp-error" }, error),
      h("section", { className: "vp-receipt" },
        h("div", null, h("span", null, "Run"), h("code", null, intake.run_id)),
        h("div", null, h("span", null, "SHA-256"), h("code", null, intake.artifact_sha256)),
        h("div", null, h("span", null, "Profiles"), h("code", null, Object.keys(intake.frozen_profiles).join(", "))),
        h("div", null, h("span", null, "Authority"), h("code", null, intake.authority_ceiling.join(", ")))
      ),
      h("pre", { className: "vp-artifact" }, artifact),
      !result && h("section", { className: "vp-decision" },
        h("label", { className: "vp-check" },
          h("input", { type: "checkbox", checked: reviewed, onChange: function (e) { setReviewed(e.target.checked); } }),
          "I reviewed the exact bytes and digest shown above"
        ),
        h("label", null, "Feedback (required for Request changes)",
          h("textarea", { value: feedback, onChange: function (e) { setFeedback(e.target.value); }, rows: 5 })
        ),
        h("div", { className: "vp-actions" },
          h(C.Button, { variant: "outline", disabled: busy || !reviewed || !feedback.trim(), onClick: function () { decide("request_changes"); } }, "Request changes"),
          h(C.Button, { disabled: busy || !reviewed, onClick: function () { decide("approve"); } }, "Approve for planning")
        )
      ),
      result && h("section", { className: "vp-card vp-result" },
        h("p", { className: "vp-kicker" }, projection.status === "DELIVERED" ? "DELIVERED" : "PENDING REPLAY"),
        h("h2", null, projection.status === "DELIVERED" ? "One bounded task created" : "Decision committed; task projection pending"),
        h("dl", null,
          h("dt", null, "Decision"), h("dd", null, h("code", null, result.decision.decision_id || "committed")),
          h("dt", null, "Task"), h("dd", null, h("code", null, projection.task_id || "not yet created")),
          h("dt", null, "Idempotency key"), h("dd", null, h("code", null, projection.idempotency_key)),
          projection.error_code && h(React.Fragment, null, h("dt", null, "Stable error"), h("dd", null, h("code", null, projection.error_code)))
        ),
        projection.status !== "DELIVERED" && h(C.Button, { disabled: busy, onClick: reconcile }, busy ? "Reconciling…" : "Retry projection")
      )
    );
  }

  registry.register("verified-pipeline", VerifiedPipelinePage);
})();
