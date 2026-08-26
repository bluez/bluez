# Security Policy

## How to Report a Potential Vulnerability?

Please report all suspected vulnerabilities by filing a draft security
advisory at
[https://github.com/bluez/bluez/security/advisories](https://github.com/bluez/bluez/security/advisories),
containing as many details as possible, including the version affected, and
any ways to reproduce or fix the problem.

Do not report suspected vulnerabilities through public channels, such as the
linux-bluetooth mailing-list or GitHub issues, until they have been disclosed
as described below.

BlueZ is maintained by volunteers, and reports are handled on a best effort
basis, with no guaranteed response time. If you have not received any
acknowledgment after two weeks, please add a comment to the draft advisory
rather than escalating to a public channel.

## Scope

This policy covers the code shipped by this repository, in particular the
`bluetoothd` and `obexd` daemons, and the libraries they install.

The test and development utilities in `tools/` and `test/` are not part of
the attack surface of a normal installation. Problems in those should be
reported as bugs using the normal process.

## AI usage

AI assistance may be used to find vulnerabilities, but a report which has not
been understood and verified by a human before being filed costs the BlueZ
developers more time than it saves. Before reporting, confirm that the issue
is real, that it is reachable in the way you describe, and that any suggested
fix makes sense. Do not file machine-generated reports unreviewed.

If AI assistance was used at any point, the report must disclose this,
including which tool and model version were used, and for what.

## Embargoed vulnerabilities

All security advisories filed through GitHub will be embargoed until
either a fix is available in the [main BlueZ repository](https://git.kernel.org/pub/scm/bluetooth/bluez.git/)
([mirror](https://github.com/bluez/bluez/)), or it has been made public
by a third-party.

GitHub security advisories have discussion fields, and those discussion fields
will stay private even after the advisory has been made public. Only trusted
BlueZ developers will have access to those comments, and unpublished advisories.
In exceptional circumstances, external security researchers or developers might
get access to advisories if BlueZ developers find it to be necessary for
assessment, coordination or publication.

## CVE number assignment

All the vulnerabilities reported through GitHub's security advisories feature
will be assigned a unique GHSA, which can be used to reference the issue
externally.

BlueZ maintainers will aim to work with either
[GitHub](https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/repository-security-advisories#cve-identification-numbers)
or [Red Hat](https://access.redhat.com/articles/red_hat_cve_program) as CNAs
to get CVE IDs assigned, on a best effort basis.

Vulnerabilities reported publicly through the linux-bluetooth mailing-list,
or in any other manner, will not be assigned CVE IDs, and BlueZ maintainers
will not be working with CNA to get a CVE ID assigned to that vulnerability.

## Disclosure

Once an issue has been discussed privately, accepted as a security issue by
BlueZ developers, a fix created, and if the severity of the issue is
high enough (usually only for critical/high), BlueZ developers will aim
to have distributions forewarned about the issue through the private
[linux-distros@vs.openwall.org](mailto:linux-distros@vs.openwall.org) mailing-list.

Note that we recommend informing BlueZ developers and working on a fix first,
before involving the `linux-distros`, as this list has a relatively short
embargo period which might not allow for much time for the BlueZ developers
to create and test robust fixes.

We will not be doing any coordinated or restricted disclosure for issues that
are considered of low or moderate severity. The advisory for such an issue
still stays private until a fix is available, as described above, but no
distribution pre-notification will be done.

## Severity assessment

Some Bluetooth functionality is gated behind the `--enable-experimental`
build option, and behind the `-E/--experimental` command-line option.

When security issues exist in such gated functionality, the severity for the
issue will be considered as `Low`, as the vulnerable code is not built or
reachable in a default installation. Reporters should not expect the score to
reflect the impact the same issue would have if the functionality were enabled
by default.

Reports should take into account the systemd sandboxing features enabled
in the configuration shipped by BlueZ upstream, if they are applicable
to the vulnerable portion of the codebase. Issues that only manifest
themselves when running unsandboxed will have their severity lowered
as appropriate.

Similarly, Denial-of-Service issues will only be considered as security
issues if they can be triggered without human intervention, or set up
on the BlueZ side, otherwise please report those problems as bugs
using the normal process.

Finally, security issues which are only possible using the root-requiring,
firmware-stack-and-radio-bypassing vHCI (virtual Bluetooth adapters usually
used for testing) will not be considered security issues either, just bugs.

## Non-disclosure agreements

The BlueZ developers are not a formal body and are therefore unable to enter
any non-disclosure agreements.
