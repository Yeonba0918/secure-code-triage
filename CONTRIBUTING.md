# Contributing

Contributions are welcome when they improve defensive code review workflows.

## Development

Run tests before opening a pull request:

```bash
python3 -m unittest discover -s tests
```

## Rule Changes

When adding or changing a rule:

- keep it defensive and repository-local
- include a remediation recommendation
- avoid printing secret values in evidence
- add a focused test
