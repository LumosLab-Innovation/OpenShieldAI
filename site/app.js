(() => {
  "use strict";

  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const reveals = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window) {
    document.documentElement.classList.add("js-ready");
    const revealObserver = new IntersectionObserver((entries, observer) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      });
    }, { threshold: 0.08 });
    reveals.forEach((element) => revealObserver.observe(element));
  }

  const root = document.getElementById("defense-flow");
  if (!root) return;

  const steps = [
    { id: "INPUT", phase: "Establish scope", title: "Start with authority.", description: "An authorized operator enrolls the asset and defines its scope. Telemetry, evidence and backup metadata enter through bounded inputs. An uploaded alert never grants access." },
    { id: "EVIDENCE", phase: "Preserve the facts", title: "Evidence, with its limits.", description: "Validate, sanitize and preserve provenance. Keep original artifacts in the operator’s evidence system; index derived facts and expose missing, stale or contradictory observations." },
    { id: "REASON", phase: "Continuous AI supervision", title: "Investigate as evidence changes.", description: "The resident scheduler tracks changed evidence and freshness across durable state. Real Codex trials through CLIProxyAPI use bounded catalog reads, deadlines and explicit degradation. The final 16-case assessment quality ties the deterministic baseline; operational AI advantage remains unproven. Models cannot grant or execute an action." },
    { id: "PROPOSAL", phase: "Plan the response", title: "Propose an exact action.", description: "A typed proposal names the asset, operation, preconditions, service impact, verification and compensation. Hypotheses remain separate from confirmed facts; a proposal carries no execution authority." },
    { id: "GATE", phase: "Check authority", title: "Permission is a boundary.", description: "Deterministic policy checks scope and state. A human approves the exact action, parameters, evidence version and expiry. Denied, stale or changed proposals return for revision." },
    { id: "ACTION", phase: "Isolated lab capability", title: "Act at a real control point.", description: "The implemented synthetic lab places its fixed ingress into maintenance after exact approval. Proxy reload may interrupt streams; this does not establish host, identity or egress containment. Actual app probes check the effect and service interruption. Production execution gates remain open." },
    { id: "VERIFY", phase: "Observe independently", title: "A receipt is not proof.", description: "Separate observations check the intended effect, legitimate-service health and application integrity. Restore validation runs in isolation. Inconclusive checks request more evidence rather than declaring success." },
    { id: "OUTCOME", phase: "Record what is known", title: "Close the loop honestly.", description: "Record verified effects, coverage gaps, residual risk and the next owner action. Retain unknown outcomes. Feed reviewed lessons back into preparedness; never infer safety from silence." }
  ];
  const diagram = root.querySelector("#architecture-diagram");
  const buttons = [...root.querySelectorAll("[data-step]")];
  const playButton = root.querySelector("#flow-play");
  const playLabel = root.querySelector("#play-label");
  const playSymbol = root.querySelector("#play-symbol");
  const announcement = root.querySelector("#step-announcement");
  let activeStep = 0;
  let playing = !reducedMotion.matches;
  let visible = false;
  let timer;

  function schedule() {
    window.clearTimeout(timer);
    if (playing && visible && !document.hidden) {
      timer = window.setTimeout(() => {
        selectStep((activeStep + 1) % steps.length);
        schedule();
      }, 5200);
    }
    diagram.classList.toggle("is-playing", playing && visible && !document.hidden);
  }

  function updatePlayback() {
    playButton.setAttribute("aria-pressed", String(playing));
    playLabel.textContent = playing ? "Pause" : "Play";
    playSymbol.textContent = playing ? "Ⅱ" : "▷";
    schedule();
  }

  function selectStep(index, manual = false) {
    activeStep = (index + steps.length) % steps.length;
    const step = steps[activeStep];
    root.querySelector("#step-counter").innerHTML = `${String(activeStep + 1).padStart(2, "0")} <span>/ 08</span>`;
    root.querySelector("#step-phase").textContent = step.phase;
    root.querySelector("#step-title").textContent = step.title;
    root.querySelector("#step-description").textContent = step.description;
    buttons.forEach((button, index) => {
      if (index === activeStep) button.setAttribute("aria-current", "step");
      else button.removeAttribute("aria-current");
    });
    steps.forEach(({ id }, index) => {
      const node = diagram.querySelector(`.node[id*="flowchart-${id}-"]`);
      if (node) node.classList.toggle("active", index === activeStep);
    });
    const nextId = steps[(activeStep + 1) % steps.length].id;
    diagram.querySelectorAll(".flowchart-link").forEach((path) => {
      const edgeId = path.getAttribute("data-id") || path.id;
      path.classList.toggle("route-active", edgeId.includes(`L_${step.id}_${nextId}_`));
    });
    if (manual) {
      playing = false;
      updatePlayback();
      announcement.textContent = `Step ${activeStep + 1} of ${steps.length}. ${step.title} ${step.description}`;
    }
  }

  buttons.forEach((button) => button.addEventListener("click", () => selectStep(Number(button.dataset.step), true)));
  root.querySelector("#step-prev").addEventListener("click", () => selectStep(activeStep - 1, true));
  root.querySelector("#step-next").addEventListener("click", () => selectStep(activeStep + 1, true));
  playButton.addEventListener("click", () => {
    playing = !playing;
    updatePlayback();
  });

  steps.forEach(({ id }, index) => {
    const node = diagram.querySelector(`.node[id*="flowchart-${id}-"]`);
    if (!node) return;
    node.setAttribute("tabindex", "0");
    node.setAttribute("role", "button");
    node.setAttribute("aria-label", `Explain step ${index + 1}: ${buttons[index].textContent.replace(/\s+/g, " ").trim()}`);
    node.addEventListener("click", () => selectStep(index, true));
    node.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        selectStep(index, true);
      }
    });
  });

  if ("IntersectionObserver" in window) {
    new IntersectionObserver((entries) => {
      visible = entries[0].isIntersecting;
      schedule();
    }, { threshold: 0.1 }).observe(root);
  } else {
    visible = true;
  }

  document.addEventListener("visibilitychange", schedule);
  reducedMotion.addEventListener("change", (event) => {
    if (!event.matches) return;
    playing = false;
    updatePlayback();
  });
  selectStep(0);
  updatePlayback();
})();
