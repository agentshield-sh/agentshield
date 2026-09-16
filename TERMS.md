# AgentShield Terms of Use

Effective date: July 1, 2026

These terms are a pre-release draft and should be reviewed by qualified legal counsel before commercial launch.

## 1. The Service

AgentShield is a diagnostic security assessment tool. It checks selected local files, configurations, packages, tooling state, and network listeners for patterns associated with known vulnerabilities, unsafe exposure, and risky configuration.

## 2. Assessment, Not Protection

AgentShield performs point-in-time checks. It is not a live protection service and does not continuously monitor or defend a device.

AgentShield does not provide or replace:

- a firewall or network access-control system
- antivirus, anti-malware, EDR, intrusion detection, or intrusion prevention
- real-time blocking, isolation, or incident response
- automatic patching, secret rotation, remediation, or recovery
- professional security assessment or legal/compliance advice

AgentShield does not guarantee that a device, account, project, network, or environment is secure. It may miss threats, vulnerabilities, exploits, or unsafe configurations. It may also report false positives.

## 3. Your Responsibilities

You are responsible for:

- deciding which paths and systems AgentShield may scan
- validating findings before acting on them
- maintaining backups and appropriate preventive security controls
- protecting exported reports because they may contain sensitive paths or configuration details
- obtaining authorization before scanning systems you do not own or control
- applying patches, rotating credentials, closing exposed services, and responding to incidents

## 4. Local Processing And Reports

The open-source scanner is designed to run locally. AgentShield does not require a cloud backend for core scans. Data can leave your device if you export, upload, publish, or otherwise share a report, or if your hosting/terminal environment captures command output.

## 5. Third-party Data And Tools

Some checks rely on operating-system tools, npm metadata, npm audit data, or third-party package information. Their availability, accuracy, and completeness are outside AgentShield's control.

## 6. No Warranty

To the maximum extent permitted by applicable law, AgentShield is provided "as is" and "as available" without warranties of accuracy, completeness, fitness for a particular purpose, non-infringement, or uninterrupted availability.

## 7. Limitation Of Liability

To the maximum extent permitted by applicable law, AgentShield contributors and operators are not liable for indirect, incidental, special, consequential, or punitive damages, or for loss of data, credentials, revenue, profits, business opportunity, or security posture arising from use of or reliance on AgentShield.

Nothing in these terms excludes or limits liability or consumer rights that cannot lawfully be excluded or limited.

## 8. Open-source License

The open-source software is also governed by the GNU Affero General Public License, version 3 or later. If these terms conflict with rights granted by the AGPL for the software itself, the AGPL controls for those software rights.

A separate commercial license is available for uses the AGPL does not suit. Any future paid AgentShield services would not be covered by the AGPL and would be governed by their own agreement. See [`LICENSING.md`](LICENSING.md).

## 9. Changes

These terms may change as AgentShield develops. Material changes should be published with an updated effective date.

## 10. Contact

Product questions and non-sensitive issues can be submitted through the AgentShield GitHub repository. Security vulnerabilities must follow [`SECURITY.md`](SECURITY.md).
