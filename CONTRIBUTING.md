# How To Contribute

## Some Ways to Contribute

- Report potential bugs.
- Suggest product enhancements.
- Increase our test coverage.
- Fix a bug.
- Implement a requested enhancement.
- Improve our guides and documentation. L3af Guides, Docs, and api godoc are deployed from this repo.

## Clone and Provision Environment

1. Make sure you have a GitHub account
2. Fork the l3afd repository to your GitHub user or organization. 
3. Clone your ${YOUR_GITHUB_USERNAME_OR_ORG}/l3afd fork into your GOPATH, and setup the base repository as upstream remote:

```
mkdir -p "${GOPATH}/src/github.com/l3af-project"
cd "${GOPATH}/src/github.com/l3af-project"
git clone https://github.com/${YOUR_GITHUB_USERNAME_OR_ORG}/l3afd.git
cd l3afd
git remote add upstream https://github.com/l3af-project/l3afd.git
```
4. Setup your [L3AF Development Environment on vagrant](https://github.com/l3af-project/l3af-arch/tree/main/dev_environment). 
5. Check the GitHub issues for [good tasks to get started](https://github.com/l3af-project/l3afd/issues). 
6. Start contributing.
7. Perform end-to-end test in dev environment.

## Pull Requests guidelines

We actively welcome your pull requests.

- If you've added code that should be tested, add tests.
- If you've changed APIs, update the documentation.
- Ensure the test suite passes.
- Make sure your code lints. 
