# Public project landing

The [GitHub Pages landing](https://lumoslab-innovation.github.io/OpenShieldAI/) presents the project's vision, architecture and a visible [benchmark ledger](https://lumoslab-innovation.github.io/OpenShieldAI/#benchmarks). It is a static showcase, not the incident-response runtime. Publishing it does not advance any implementation or acceptance gate.

## Benchmark publication

The ledger is plain English HTML with a complete final Codex/baseline table, the separate post-hoc v2 lookup comparison, all completed model attempts, measured control/recovery effects, Go performance, historical Docker/Chrome/REA trials and the 24-case coverage boundary. Native expandable details keep dense evidence readable; table values and source links remain available without JavaScript. Tables use captions, row/column headers and labelled keyboard-focusable horizontal scroll regions. The existing mint/graphite visual system and generated hero/Mermaid diagram are preserved.

The [metric audit](lab/METRICS_AUDIT.md) maps every published number to safe frozen evidence. Keep failed/degraded trials visible beside successful outcomes. Distinguish engineering assertion counts, independent attack samples, inference decisions, model reservations, elapsed boundaries and historical validation snapshots. Do not pool overlapping suites or credit deterministic enforcement to AI. The current 16-case corpus is public engineering regression material, not a held-out efficacy estimate; coarse assessment quality ties and operational AI advantage remains unproven.

When results change, update README and the static ledger together against the exact report and normalized source/corpus commitments. `#ai-benchmark` cells expose numeric `data-metric`, `data-arm` and `data-value` attributes for publication consistency checks; visitors see the formatted values directly. Keep historical records labelled and immutable, disclose protocol changes, and link current CI independently of captured historical test counts. No landing script calls the model or reads the operator proxy.

The publication checks run with `python -m unittest discover -s scripts -p 'test_*.py'`: they compare both public AI tables with the frozen JSON, require links to failed attempts and every measurement family, and verify normalized trial hashes. The 2026-10-24 local Chrome check exercised 1440 px desktop, 390/320 px mobile, keyboard details, manual graph stepping/pause, reduced motion and no-JavaScript tables. The primary mobile AI table fits without horizontal scrolling; wider detailed tables scroll inside their labelled regions. No page errors or failed local assets were observed. These are showcase checks, not security-efficacy measurements.

## Source and deployment

Only `site/` is published by [the Pages workflow](../.github/workflows/pages.yml). HTML, CSS, JavaScript and assets use relative paths so the project URL prefix works. No backend, credentials, analytics, customer telemetry or runtime AI service is part of the landing. The repository About website points to this URL after deployment is verified.

Use Python 3.11+ for a local preview:

```text
python -m http.server 8784 --bind 127.0.0.1 --directory site
```

Open `http://127.0.0.1:8784/`. Test desktop, narrow mobile, keyboard controls, graph pause/step behavior, reduced motion and browser console/network. Passing these checks validates the showcase only.

## Visual system

The README and navigation use the generated S/shield logo; the landing hero uses the separate guardian [artwork](assets/IMAGE_GENERATION.md). Both share near-black/graphite surfaces, white type and a restrained mint accent. Public landing and README copy are in English. Contributor/star badges use real third-party GitHub data, never fabricated counts; those services may be unavailable independently of this site.

## Diagram authoring

The authored [Mermaid source](../site/defense-flow.mmd) defines the proposed defensive flow. Its SVG is pre-rendered and embedded in the HTML so visitors do not download or execute Mermaid. The page adds a controlled educational walkthrough; animation does not represent a live incident or an executing security action. A static diagram and text explanation remain available when JavaScript is unavailable. Respect reduced-motion preferences and provide a pause control.

Render with the pinned authoring CLI (not a site runtime dependency):

```text
npx --yes --package @mermaid-js/mermaid-cli@11.12.0 mmdc -i site/defense-flow.mmd -o site/assets/defense-flow.svg -c site/mermaid.config.json -b transparent
```

After rendering, replace the region between `BEGIN GENERATED MERMAID` and `END GENERATED MERMAID` in `site/index.html` with the regenerated SVG. Retain the markers. Keeping the chart inline gives visitors a readable no-JavaScript diagram and lets the walkthrough highlight actual nodes.

The renderer needs a supported local Chrome/Chromium. A workstation-specific Puppeteer configuration can select its executable with `-p`; keep that local path out of published configuration. Use an isolated npm cache if the host cache is broken; do not delete a shared cache. Review the SVG after regeneration and rerun the interactive walkthrough because its node IDs are referenced by the page.

Keep `securityLevel: strict`, disable HTML labels and do not accept visitor-supplied diagram sources or arbitrary SVG URLs. Diagram changes must retain the policy/approval boundary before execution, lab-only action scope, unpassed production gates and separate outcome verification.
