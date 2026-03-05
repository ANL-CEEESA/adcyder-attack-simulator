# Development Standards for DOE Lab Research
Refer to README.md, *.md, *.mmd, Makefile, and .gitlab-ci.yml as necessary to help understand code and workflow.

## Communication and Working Style
- Provide direct, technically precise responses. Do not flatter, hedge excessively, or agree for the sake of agreement.
- When proposing a design or implementation approach, state tradeoffs and risks explicitly rather than presenting one option as obviously correct.
- If a request is ambiguous or underspecified, ask clarifying questions before generating code. Do not guess at requirements.
- When a task involves multiple reasonable approaches, briefly present the options with tradeoffs and ask for a decision rather than choosing silently.
- Distinguish clearly between things you are confident about and things you are uncertain about. Say "I'm not sure about X" when applicable.

## Code Generation Rules
- Always provide complete diffs - never use placeholder comments like "rest of code remains the same"
- Apply PhD-level technical depth with security-first analysis
- When generating research code intended for publication, include sensitivity analysis scaffolding: functions to perturb inputs/hyperparameters and verify output behavior changes appropriately.
- Consider attack vectors, defense strategies, and compliance requirements

## Development Environment
- **Python**: Latest version with full type hints (mypy --strict compliance)
- **Package Management**: micromamba (often inside Docker containers)
- **Build System**: Makefile orchestration
- **Code Formatting**: `make black` for Python formatting
- **Security Checks**: `make security` (bandit/pip-audit)
- **Type Checking**: `make type-check` (mypy)
- **Testing**: `make test-unit` and `make test-integration` (pytest)
- **Dependencies**: X.Y.* pinned versions only

## Python File Structure
**Every Python file must start with a docstring including:**
- Module name and single-sentence purpose
- Description of public interface (what callers need to know)
- Non-obvious design decisions or constraints
- Scale docstring detail to module complexity; a 30-line utility module does not need the same documentation as a training pipeline

**Import Organization (with blank lines between groups):**
1. Standard library imports (alphabetical)
2. Standard library 'from' imports (alphabetical)
3. Third-party package imports (alphabetical)
4. Third-party 'from' imports (alphabetical)
5. Local project imports (alphabetical)
6. Local project 'from' imports (alphabetical)

## Code Standards
- **Type Safety**: Full type hints required, mypy --strict compliance
- **DRY Principle**: Eliminate code duplication wherever possible
- **Logging**: Use logging module instead of print statements (debug/info/warning/error/critical)
- **Validation**: Pydantic models for input validation
- **Error Handling**: Custom exceptions with specific exception handling
- **Fail Loudly**: Never implement silent fallbacks, default substitutions, or graceful degradation that masks errors. If something fails, raise an exception with a clear message. Do not catch exceptions and return default values, empty collections, or None unless the caller explicitly handles that case. Missing configuration, unavailable services, and unexpected data should crash immediately with actionable error messages, not silently proceed with degraded behavior.
- **External APIs**: Use tenacity + ratelimit for robust handling, diskcache for client-side caching
- **Memory Efficiency**: Generators/iterators for large datasets, tqdm for progress tracking
- **Concurrency**: Consider parallel processing where appropriate using joblib
- **Tool Preferences**: httpx over requests, playwright over selenium, pytorch over tensorflow, polars over pandas
- **Dependencies**: When adding or changing a dependency, explicitly state what was added and why. Do not add packages that duplicate functionality already available in the environment. Containerized environments must rebuild cleanly without layer caching.

## Project Structure
**For new projects:**
- Code in `src/` (single/no container) or `*/src/` (multi-container projects)
- Tests always in `tests/` at project root
- Organize src by functionality, for example: `core/`, `models/`, `services/`, `api/`, `utils/`
- Use snake_case naming, `__init__.py` files where required

**For existing projects:** Keep existing structure but apply standards within it

## Configuration Management
- `settings.py` in src/ for main configuration
- `settingslocal.py` for sensitive/local overrides (gitignored)
- Use `.env` files when appropriate for Docker containers
- No hardcoded values in source files

## Clean Code Principles
- **Naming**: Meaningful, pronounceable, searchable names. No abbreviations or mental mapping
- **Functions**: 20-30 lines max, single responsibility, ≤3 parameters, no flag arguments
- **Classes**: Single responsibility, small classes, few instance variables, composition over inheritance
- **Error Handling**: Use exceptions not error codes, meaningful messages with context
- **Comments**: Explain WHY not WHAT, avoid redundant comments, keep current with code changes
- **Structure**: No duplication, consistent formatting, avoid deep nesting (early returns), prefer immutable objects

## Research Code Standards

### Decomposition and Verifiability
* Never generate monolithic ML training pipelines. Break into independently verifiable components: data loading/preprocessing, model architecture, loss function, training loop, evaluation. Each component must have a testable contract before integration.
* For every ML component, generate verification checks alongside the implementation: known-input/known-output tests for loss functions, shape assertions at each pipeline stage, parameter count validation for architectures, gradient norm logging for training loops.
* When building a training pipeline, always include a sanity check that overfits a small synthetic or subset dataset before full training. If the model can't memorize 5-10 examples, something is wrong.

### Guarding Against Silent Failures
* Never hard-code values that should be computed. If a constant appears in ML code, add a comment explaining its derivation and a test that validates it.
* When implementing train/test splits or cross-validation, explicitly verify no data leakage: assert zero overlap between splits, verify preprocessing is fit only on training data, log dataset sizes at each stage.
* When debugging or modifying ML code, never silently change architecture, hyperparameters, or preprocessing without explicitly flagging the change and explaining the rationale. Every modification to a working pipeline must be logged as a discrete, documented change.
* Evaluation metrics must be tested against hand-computed examples before use. Include at least two test cases with manually verified expected values.

### Audit Trail and Reproducibility
* All ML experiments must pin random seeds, log library versions, and be runnable in a containerized environment.
* Maintain a changelog within the code or an accompanying doc that tracks what changed, why, and what verification was performed after each change.

### Agent Behavior Rules
* Before implementing any non-trivial task, propose a plan: decomposition into components, verification strategy for each, and integration approach. Wait for approval before writing code.
* When making design decisions during implementation (algorithm choice, library selection, architectural patterns), document the decision and rationale in a code comment. Do not make silent design choices.
* After completing an implementation, provide a summary of: what was built, what design decisions were made, what was tested, what was NOT tested, and what assumptions were made. Explicitly call out areas of lower confidence.
* When generating ML or scientific code, flag any place where results could be silently wrong despite passing tests. Examples: broadcasting behavior that masks shape errors, default parameters that may not suit the use case, metrics that could be misleading for imbalanced data.
* Do not add fallback behavior, default return values, or try/except blocks that swallow errors unless explicitly requested. The default behavior on any unexpected condition is to raise an exception and halt. If you are tempted to add a fallback, instead raise an error with a message explaining what went wrong and what the caller should do about it.
* If you encounter a bug that doesn't resolve within two iterative attempts, stop and report: what the expected behavior is, what the observed behavior is, what you tried, and your best hypothesis. Do not keep trying variations silently.
* When asked to implement an ML pipeline or experiment, start by proposing the decomposition and verification strategy for approval before writing implementation code.
* Do not present passing unit tests as evidence that ML code produces scientifically valid results. Tests verify implementation correctness; scientific validity requires experimental verification (ablation, sensitivity analysis, baseline comparison). Distinguish these explicitly.

## Documentation Standards
- Every research project must have a README.md that explains: what the project does, how to reproduce results, what the expected outputs are, and what environment is required.
- For publication-bound code, include a METHODS.md or equivalent that maps code components to paper sections/claims. A reviewer should be able to trace any result in the paper to the code that produced it.
- Architecture decisions that affect scientific validity (choice of optimizer, loss function, data splitting strategy, evaluation protocol) must be documented with rationale, not just implemented.

## Experiment Management
- All experiment runs must log: git commit hash, full configuration/hyperparameters, random seeds, library versions, start/end timestamps, and hardware used.
- Results must be reproducible from logged parameters. If rerunning with the same config and seed does not produce the same result, that is a bug.
- Never overwrite previous experiment results. Use timestamped or hash-identified output directories.
- Intermediate checkpoints for long-running training must be saved at configurable intervals.

## Git Workflow
**Conventional Commits:** `<type>[scope]: <description>`
- Types: feat, fix, docs, style, refactor, test, chore, perf, ci, build, revert
- Subject under 50 chars, imperative mood ('add' not 'added')
- Separate subject from body with blank line, wrap body at 72 chars
- Explain WHY not implementation details
- Examples: `feat(auth): add OAuth2 integration`, `fix: resolve memory leak in parser`

**Branch Strategy:** Always push to feature branches, create merge/pull requests to main

## Container Standards
- Official tagged base images, non-root users, .dockerignore files
- One process per container principle
- Use Docker (single container) or Docker Compose (multiple containers)

## Repository Rules
- **Source code ONLY** - no docs/binaries/data/results/logs in git
- All code must past `make lint` and (if available) `make type-check` and `make test`
- When testing code, use the same Container/Environment command prefixes found in the Makefile
- Use .gitignore to prevent accidental commits

## Security Requirements
- All code must pass `make security` analysis
- No sensitive data in source code (use environment variables)
- Security-first implementation approach
- Document security assumptions and limitations
- Follow principle of least privilege

## Automation & CI/CD
- GitLab CI workflow in `.gitlab-ci.yml`
