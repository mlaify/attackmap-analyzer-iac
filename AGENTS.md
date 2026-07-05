# AGENTS.md

## Project
This repository contains an AttackMap analyzer.

AttackMap analyzers live under:
- `github.com/mlaify`

This repo should implement one analyzer cleanly against the AttackMap core contract.

## Analyzer responsibilities
This analyzer should:
- detect whether it applies to a target repository
- emit structured signals
- remain heuristic but explainable
- be easy to test with fixtures

This analyzer should not:
- render final reports
- own global scoring logic
- depend on unstable core internals where avoidable

## Engineering rules
- keep the analyzer broad and reusable unless it is explicitly an overlay analyzer
- emit structured data only
- prefer minimal dependencies
- use small, readable fixtures
- preserve compatibility with the AttackMap analyzer contract
- document limitations honestly

## Testing
Add focused unit tests and fixture-based tests.
Validate:
- detection
- extraction quality
- edge cases relevant to the analyzer domain

## Workflow
Before making changes:
1. inspect the current analyzer and tests
2. identify the smallest useful improvement
3. implement it
4. run the smallest relevant tests
5. summarize changed files, commands run, results, and limitations