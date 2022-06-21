# How To Contribute

## Some Ways to Contribute
- [Getting started with L3AF](#getting-started-with-l3af)
- [Report potential bugs](#report-potential-bugs)
- [New features or product enhancements](#new-features-or-product-enhancements)
- [Submitting a patch that fixes a bug](#submitting-a-patch-that-fixes-a-bug)
- [Coding style](#coding-style)
- [Guidelines for pull requests](#guidelines-for-pull-requests)
- [Improve our guides and documentation](#improve-our-guides-and-documentation)
- [Increase our test coverage](#increase-our-test-coverage)

### Getting started with L3AF

See [L3AF](https://wiki.lfnetworking.org/display/L3AF/Getting+Started+with+L3AF)

### Report potential bugs

First, **ensure the bug was not already reported** by searching on GitHub under
[Issues](https://github.com/l3af-project/l3afd/issues).

If you did not find a related bug, you can help us by
[submitting a GitHub Issue](https://github.com/l3af-project/l3afd/issues/new).
A good bug report provides a detailed description of the issue and step-by-step instructions
for reliably reproducing the issue.

We will aim to triage issues in [weekly TSC meetings](https://wiki.lfnetworking.org/display/L3AF/Community+Meetings).
In case we are unable to repro the issue, we will request more information from you. There will be a waiting period of
2 weeks for the requested information and if there is no response, the issue will be closed. If this happens,
please reopen the issue if you do get a repro and provide the requested information.

If you found a security issue, please do not open a GitHub Issue, and instead [email](mailto:security@lists.l3af.io) it in detail.

### New features or product enhancements

You can request or implement a new feature by [submitting a GitHub Issue](https://github.com/l3af-project/l3afd/issues/new).
and communicate your proposal so that the L3AF community can review and provide feedback. Getting
early feedback will help ensure your implementation work is accepted by the community.
This will also allow us to better coordinate our efforts and minimize duplicated effort.

### Submitting a patch that fixes a bug

Fork the repo and make your changes. Then open a new GitHub pull request with the patch.

* Ensure the PR description clearly describes the problem and solution. Include the relevant issue number
  if applicable.

### Guidelines for pull requests

Great, you want to directly contribute to the l3af project and submit a pull request.
It is recommended prior to working on a PR to submit an issue in github for the change you want
to make describing the change and context around it. This gives the l3af maintainers a chance to review
the issue and provide feedback and work with you on the change. If you have any questions, please
feel free to reach out to the l3af maintainers via [Slack](https://app.slack.com/client/T02GD9YQJUT/C02GRTC0SAD) or
[mail](main@lists.l3af.io) group. Below are some general guidelines to help ensure a successful PR approval.

- Provide background why you are making the change and the issue it addresses
- List what is changing and provide a high-level summary of the change
- List any relevant dependencies linked to this change
- Describe the tests that you ran to verify your changes and add/update test cases
- Update relevant docs, especially if you've changed APIs
- Ensure all GitHub CI/CD checks pass

### Coding Style

See [uber-go](https://github.com/uber-go/guide/blob/master/style.md)

### Improve our guides and documentation

We look forward to contributions improving our guides and documentation.
Documentation should be written in an inclusive style. The [Google developer documentation](https://developers.google.com/style/inclusive-documentation)
contains an excellent reference on this topic.

### Increase our test coverage

Increase the code coverage by adding tests. PRs are expected to have 100% test coverage for added code. This can be
verified with a coverage build. If your PR cannot have 100% coverage for some reason please clearly explain why when
you open it. Run your tests and get coverage locally

```bash
go test -race -covermode=atomic -coverprofile=coverage.out
```

## Developer Certificate of Origin (DCO)

The [Developer Certificate of Origin](https://developercertificate.org/) is a lightweight way for contributors
to certify that they wrote or otherwise have the right to submit the code they are contributing to the project.
This App enforces the Developer Certificate of Origin on Pull Requests. It requires all commit messages to contain
the ```Signed-off-by``` line with an email address that matches the commit author.

## Governance

Please refer to the [governance repo](https://github.com/l3af-project/governance) for Project Charter, Code of Conduct,
Release Process, and Committee Members.
