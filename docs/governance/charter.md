# ABC research governance

ABC maintains one source repository for historical and contemporary cryptography with independently scoped implementation, target, and release evidence. Commercial certification and consulting are outside the charter. Research packages are supported only by the explicitly recorded checks for their exact version and target.

## Responsibilities

| Responsibility | Assignment |
| --- | --- |
| Repository administrator and publication authority | Repository owner to designate |
| Release reviewer and backup reviewer | Vacant |
| Formal specification reviewer and backup | Vacant |
| Upstream continuity and advisory maintainer | Vacant |
| Security incident contact and backup | Vacant |

Maintainers publish a tested support matrix and explicit end-of-support date before promising a supported release. Research snapshots carry no response-time or long-term maintenance commitment. Maintain a documented migration path for supported API or format changes. If coverage or personnel fall below the requirements, mark the affected profile unsupported or end-of-life and record the effective date.

## Decisions and reviews

An RFC states the affected interfaces, change rationale, independent sources, tests, compatibility, security boundaries, and migration. A reviewer distinct from the author checks the result. Record the accepted decision, reviewer identity, and the exact source and evidence revisions. Changes affecting proof trust, artifact policies, or required checks use the authorized repository review path for the trusted baseline. Automated assistants can draft proposals, run checks, and update working records. A designated human supplies independent approval.

Use the repository’s designated private security reporting channel once a contact is assigned. A maintainer triages affected releases, coordinates patches and disclosure, and publishes scoped migration guidance. The research phase has no staffed private reporting or support service. Record upstream notices and affected version ranges without reproducing exploit procedures.
