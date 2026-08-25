# Security Policy

## How to Report a Potential Vulnerability?

If you are reporting a not-yet released or urgent issue, please file a draft
security advisory at
[https://github.com/bluez/bluez/security/advisories](https://github.com/bluez/bluez/security/advisories),
containing as many details as possible, including the version affected, and
any ways to reproduce or fix the problem.

## AI usage

If the vulnerability was found using AI assistance the reporter needs to
disclose that within the report, also needs to mention which AI was used
during the processes.

## Embargoed vulnerabilities

All security advisories filed through GitHub will be embargoed until
either a fix is available in the [main BlueZ repository](https://git.kernel.org/pub/scm/bluetooth/bluez.git/)
([mirror](https://github.com/bluez/bluez/)), or it has been made public
by a third-party.

GitHub security advisories have discussion fields, and those discussion fields
will stay private even after the advisory has been made public. Only trusted
BlueZ developers will have access to those comments, and unpublished advisories.
In exceptional circumstances, outside security developers might get access
to advisories if BlueZ developers find it to be necessary for assessment,
coordination or publication.

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

We will not be applying any further embargo, or do any restricted disclosure
for issues that are considered of low or moderate severity.

## Severity assessment

Some Bluetooth functionality is gated behind the `--enable-experimental`
build option, and behind the `-E/--experimental` command-line option.

When security issues exist in such gated functionality, the security
level for the issue will be considered as `Low`. This will be done by
setting the following CVSS fields:

- *Privileges Required*: `High` (requires having an experimental build, and the daemon running as experimental)
- *Confidentiality*, *Integrity* and *Availability*: `Low`

Reports should take into account the systemd sandboxing features enabled
in the configuration shipped by BlueZ upstream, if they are applicable
to the vulnerable portion of the codebase. Issues that only manifest
themselves when running unsandboxed will have their severity lowered
as appropriate.

Similarly, Denial-of-Service issues will only be considered as security
issues if they can be triggered without human intervention, or set up
on the BlueZ side, otherwise please report those problems as bugs
using the normal process.

## Non-disclosure agreements

The BlueZ developers are not a formal body and therefore unable to enter
any non-disclosure agreements.
