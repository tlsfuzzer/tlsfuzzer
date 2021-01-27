<!-- Provide a general summary of your proposed changes in the Title field above -->

### Description
<!-- Describe your changes in detail below -->

### Motivation and Context
<!-- Describe why the change is introduced, if it solves an issue add "fixes #1"
with a correct number -->

### Checklist
<!-- go over following points. check them with an `x` if they do apply,
(they turn into clickable checkboxes once the PR is submitted, so no need
to do everything at once)

if you're unsure about any of those items, just ask in comment to PR

if the PR resolves an issue, please add further checkboxes that describe the
action items or test scenarios from it
-->

- [ ] I have read the [CONTRIBUTING.md](https://github.com/tomato42/tlsfuzzer/blob/master/CONTRIBUTING.md) document and my PR follows [change requirements](https://github.com/tomato42/tlsfuzzer/blob/master/CONTRIBUTING.md#change-requirements) therein
- [ ] the changes are also reflected in documentation and code comments
- [ ] all new and existing tests pass (see CI results)
- [ ] [test script checklist](https://github.com/tomato42/tlsfuzzer/wiki/Test-script-checklist) was followed for new scripts
- [ ] new test script added to `tlslite-ng.json` and `tlslite-ng-random-subset.json`
- [ ] new and modified scripts were ran against popular TLS implementations:
  - [ ] OpenSSL
  - [ ] NSS
  - [ ] GnuTLS
- [ ] required version of tlslite-ng updated in requirements.txt and README.md
