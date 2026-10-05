## What changes and why
<!-- One paragraph. The reviewer reads this before the diff. -->


## User story (required)
<!-- Replace NN with the story issue of csp-docs. A base scaffold pull request (structure only) writes:
     "Not applicable: base scaffold, structure only". -->
Refs: code-corhuila/csp-docs#NN


## How it was tested
- Unit tests:
- HTTP / integration tests:
- `ci.yml` result:


## Size
<!-- Run: git diff --numstat origin/develop...HEAD -->
Added: · Deleted: · Total:  (limit 400, excluding tests and generated files)


## Promotion trail (only for pull requests into `qa` or `main`)
<!-- List the original commits this pull request re-applies.
     Every commit must carry the line "(cherry picked from commit <sha>)". -->
-


## Checklist
- [ ] Meets the acceptance criteria of the user story (or is a base scaffold, not applicable)
- [ ] Local validation passes (build + tests)
- [ ] Under 400 changed lines, excluding tests and generated files
- [ ] Title follows Conventional Commits
- [ ] No secrets in code, `.env.example` or workflows
- [ ] No schema or migration in this repository: they belong only to `csp-auth-db`
- [ ] Contract respected (OpenAPI and events of `csp-docs`)
- [ ] Into `qa` or `main`: every commit was re-applied with `git cherry-pick -x`
