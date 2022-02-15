# How To Contribute

## Some Ways to Contribute

- Report potential bugs
- Suggest product enhancements
- Increase our test coverage
- Fix a bug
- Implement a requested enhancement
- Improve our guides and documentation
- Contribute code

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

Great, you want to directly contribute to the l3af project and submit a pull request.
It is recommended prior to working on a PR to submit an issue in github for the change you want
to make describing the change and context around it. This gives the l3af team a chance to review
the issue and provide feedback and work with you on the change. If you have any questions, please
feel free to reach out to the l3af team via [Slack](https://app.slack.com/client/T02GD9YQJUT/C02GRTC0SAD) or
[mail](main@lists.l3af.io) group. Below are some general guidelines to help ensure a successful PR approval.

- Provide background why you are making the change and the issue it addresses
- List what is changing and provide a high-level summary of the change
- List any relevant dependencies linked to this change
- Describe the tests that you ran to verify your changes and add/update test cases
- Update relevant docs, especially if you've change API's
- Ensure all tests pass and that your code lints
