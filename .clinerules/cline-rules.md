## Execution Behavior
- Do not summarize previous tasks or output unless requested.
- Never include placeholder code (e.g., `TODO`, `pass`, `raise NotImplementedError`).
- Emit complete diffs only — no ellipses, no implied continuation.
- All responses must be minimal, complete, and deterministic.
- Always assume `*.md`, `*.mmd`, `.gitlab-ci.yml`, and Makefile are part of context.
- Truncate shell command output to 40 lines unless instructed otherwise.
- For large files, use `rg`, `sed`, `jq`, or other tools to extract only needed parts.
- Use markdown formatting with fenced code blocks for all returned content.
- When approaching context window limit, advise the user to summarize and start a new task

## Development Environment
- Python: latest available with full type hints (mypy --strict compliance)
- Package management: micromamba; environment-dev.yml at project root for development environment, environment.yml for production environment(s) (may have multiple in Docker container subdirectories, but should all be installed into the dev environment on make init)
- Build orchestration: Makefile
- Build development environment: `make init`
- Build production environment: `make build`
- Check code formatting: `make lint` (with Black)
- Apply code formatting: `make black` (with Black)
- Type checking: `make type-check` (with mypy)
- Security: `make security` (with bandit, pip-audit)
- Testing: `make test-unit`, `make test-integration`
- When using containers: `make start`, `make stop`, `make restart` (start/stop), `make rebuild` (build/restart)
- Clean up: `make clean`: Caches, containers and resources, micromamba environment
- Dependencies: pinned as X.Y.* only
- Execute code with:
  ```bash
  docker compose exec <container> micromamba run -n <env> bash -c '<COMMAND>'
  ```

## Project Organization
- `src/` contains main project code
  - Organize by domain: `core/`, `models/`, `services/`, `api/`, `utils/`
- `tests/` mirrors `src/` layout; all tests live here
- `reports/` if there are any latex or other summary outputs
- `__init__.py` required where appropriate
- Use snake_case for files/functions, PascalCase for class names
- Configuration lives in `src/settings.py`, with overrides in `src/settingslocal.py`
  - settings.py should not have any logic, it should only be for settings values
  - Check a settingslocal.template.py into git, exclude settingslocal.py in .gitignore
- Use `.env` for secrets and runtime values
  - Check a .env.template into git, exclude .env in .gitignore

## Code Guidance

### Code Generation Standards
- Always emit valid, executable code.
- Full type hints required on all function and method definitions.
- Follow DRY principle; avoid duplicated logic.
- Logging: use Python `logging`, not `print`.
- Use Pydantic for input validation.
- Use tenacity+ratelimit for API calls; diskcache for caching.
- Memory handling: use generators, iterators, and tqdm.
- Prefer: httpx > requests, playwright > selenium, polars > pandas, torch > tensorflow.
- Prefer Dask for HPC workflows; use PBS Pro job submission semantics.

### File Structure & Imports
- Every Python file must start with a structured docstring:
  - Module name and brief description
  - Detailed explanation of purpose
  - 3–4 feature sections (3–5 bullets each)
  - Use cases (3–5 items)
  - Overall less than 50 lines
- Import grouping (with spacing between groups):
  1. Standard library
  2. Standard `from` imports
  3. Third-party libraries
  4. Third-party `from` imports
  5. Local project modules
  6. Local `from` imports

### Testing Standards
- All tests must:
  - Use either `@pytest.mark.unit` or `@pytest.mark.integration`
  - Pass `make type-check`, `make security`, `make test`
- Coverage requirements:
  - Unit: ≥80%
  - Integration: ≥60%
  - Security-critical code: 100%
- Tests must be deterministic with fixed seeds
- Teardown must clean up DB/state

### Clean Code Guidelines
- Naming: readable, pronounceable, searchable (no abbreviations)
- Functions: single responsibility, ≤50 lines, ≤5 parameters, no flag args
- Classes: small, cohesive; use composition over inheritance
- Structure: avoid deep nesting; use early returns
- Comments: explain "why", not "what"; keep updated
- Error handling: use custom exceptions, no silent failures

## Rule Override Protocol
When rules must be bypassed:
1. **Document the exception** - Explain why the rule doesn't apply
2. **Justify the trade-off** - What benefit outweighs rule adherence
3. **Provide mitigation** - How you address the rule's underlying concern
4. **Mark clearly** - Use comments like `# ESCAPE HATCH:` for searchability

### Common Valid Overrides
- Performance-critical code (profiling data required)
- External system constraints (HPC, embedded, legacy systems)
- Research prototypes (time-bounded exceptions)
- Mathematical algorithms (domain-specific structure)
- Third-party API limitations (beyond your control)

## Reports and Presentations
- Use LaTeX as the output format for structure reports and presentations
- By default, use the ACM conference class for reports and the Beamer template for presentations
- Compile to PDF with pdflatex

### Report Guidance

#### Section-Level Content Principles

- One clear objective per section - Each section should advance a single aspect of your argument
- Evidence-backed claims - Support every assertion with citations, data, or logical reasoning
- Smooth transitions - End each section with a bridge to the next topic
- Contribution tracking - Explicitly connect each section back to your stated contributions

#### LaTeX Technical Standards

- Professional tables - Always use booktabs (\toprule, \midrule, \bottomrule)
- Vector graphics - Use TikZ for technical diagrams; avoid raster images when possible
- Proper citations - Integrate BibTeX references naturally into sentence flow
- Figure placement - Use [tb] positioning and appropriate captions (above tables, below figures)

#### Writing Quality Control

- Quantitative precision - Include specific metrics, error bounds, and statistical significance
- Active voice preference - Write clearly and directly about your work
- Consistent terminology - Define technical terms once and use them consistently throughout
- Reproducible details - Provide sufficient implementation specifics for replication

#### Cross-Reference Integrity

- Label everything - Use descriptive labels for sections, figures, tables, and equations
- Forward/backward coherence - Ensure references to other sections remain valid as content evolves
- Citation completeness - Verify all \cite{} commands have corresponding BibTeX entries

### Presentation Guideance

#### Content Structure and Flow

- One concept per slide - Avoid cramming multiple ideas onto a single slide
- Logical progression - Each slide should build naturally from the previous one
- Clear section breaks - Use frame breaks and section titles to segment topics
- Consistent slide timing - Aim for 1-2 minutes of speaking time per slide

#### Visual Hierarchy and Typography

- Large, readable fonts - Minimum 24pt for body text, 32pt+ for titles
- Limited text density - Maximum 6-7 lines of text per slide, preferably fewer
- Bullet point discipline - Use parallel structure and limit nesting to 2 levels
- Emphasis sparingly - Bold or color only the most critical 2-3 words per slide

#### Technical Beamer Implementation

- Theme consistency - Choose one theme and stick with it throughout
- Color accessibility - Ensure sufficient contrast ratios (4.5:1 minimum)
- Frame titles - Every frame should have a descriptive title
- Navigation aids - Include slide numbers and section indicators for longer presentations

#### Audience Engagement Mechanics

- Interactive elements - Use \pause, \only, and \uncover to reveal content progressively
- Visual anchors - Include diagrams, charts, or code blocks to break up text-heavy slides
- Transition cues - Signal topic changes with clear verbal and visual indicators
- Takeaway emphasis - End sections with summary slides highlighting key points

#### Code and Technical Content

- Syntax highlighting - Use appropriate lstlisting or minted environments
- Readable code blocks - Limit to 10-15 lines per slide, use appropriate font sizes
- Step-through explanations - Break complex algorithms across multiple slides

## Git and CI/CD
- All commits follow Conventional Commits:
  - Format: `<type>[scope]: <description>`
  - Types: feat, fix, docs, style, refactor, test, chore, perf, ci, build, revert
- Pipeline defined in `.gitlab-ci.yml`; blocks merge if any rule fails
- Always commit to feature branches; open MR to main
- Only code in git; exclude logs, binaries, data, output
- Enforce with `.gitignore`

## Security Rules
- Always validate input; never trust client input
- No hardcoded secrets; use env vars or ignored config
- Apply least privilege for roles, access, and file permissions
- Code must pass all security checks
- Document security trade-offs and assumptions

## PhD-Level Technical Depth
- First Principles Thinking: Deconstruct problems to their fundamental truths rather than relying solely on analogies or existing solutions.
- Comprehensive Understanding: Possess a deep grasp of the entire system, its dependencies, and the broader scientific/domain context.
- Proactive Problem Solving: Anticipate challenges, edge cases, and future scalability/maintenance needs before they manifest.
- Evidence-Based Decisions: Ground technical choices in data, theoretical understanding, and thorough analysis.
- Defensive Design: Engineer solutions with robustness and resilience in mind, accounting for failures and unexpected inputs.

## Prompting Constraints
- No conversational fluff
- No speculative answers
- Be concise, deterministic, and focused
- Break complex tasks into sequenced steps
- Use markdown or diff format in all responses
