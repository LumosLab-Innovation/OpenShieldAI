# Public project landing

The [GitHub Pages landing](https://lumoslab-innovation.github.io/OpenShieldAI/) presents the project's vision, architecture and links to measured lab evidence. It is a static showcase, not the incident-response runtime. Publishing it does not advance any implementation or acceptance gate.

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
