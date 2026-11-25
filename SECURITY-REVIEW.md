# GitHub Pages security review and recovery

Audit date: 25 November 2026 (Asia/Bangkok). Baseline commit: `074dba5c6b8dfbc1cd4758c843f05b676621f337`.

## Confirmed status

The supplied screenshot shows Safari's **Deceptive Website Warning**. On the audit date, Google's public Transparency Report also reported social-engineering content for both [the host](https://transparencyreport.google.com/safe-browsing/search?url=sanwithz.github.io) and [this project prefix](https://transparencyreport.google.com/safe-browsing/search?url=sanwithz.github.io%2FProject-Guildance%2F). Both reports displayed a last-updated date of 24 November 2026. These broad reports do not identify the specific triggering URL or code. Their date is not a reliable first-detection timestamp.

The repository has one original HTML file: `ระบบจัดการทุนการศึกษา/index.html`. It is a Thai offline **manual**, not the scholarship application it describes. Its original source contains no login form, password input, remote resource, API call, upload, download, iframe, or external redirect. The sole input is local search; script renders search text using `textContent`. Only the theme preference is saved in browser storage.

Passive HTTPS requests with a default user agent and an iPhone Safari user agent plus Google referrer both returned HTTP 200 without redirects. Both bodies were byte-identical to the baseline file (77,220 bytes; SHA-256 `786e875081d0d5928948e5cffa5357b45ecc25c8d5e46525055c7b8dbccbdb8d`). This rules out a mismatch in those two responses; it is not proof against every possible conditional response.

Pages settings inspected during the audit: source `main` at `/`, legacy branch build, no custom domain, HTTPS enforced. The connector did not expose the Pages-settings endpoint, so that read used GitHub's API through the installed CLI.

## Changes in this proposal

- Add a restrictive meta Content Security Policy. Only the exact existing inline script and stylesheet hashes are allowed. Network requests, forms, base URLs, and objects are denied; other resource types inherit `default-src 'none'`.
- Add `no-referrer` and turn off search autocomplete.
- Identify the publisher, link to the public source/reporting location, and clearly state that the page takes no passwords or student records and keeps searches on the device.
- Add `python3 scripts/check-security.py` to verify the policy hashes and passive-document constraints after edits.

This is defense in depth and clearer attribution. It does not establish that this manual caused the warning or guarantee removal. The original safety caveats remain visible. Meta CSP cannot enforce `frame-ancestors`; blocking framing requires an HTTP response header from hosting that supports it. Do not add an unsupported meta directive and assume framing is prevented.

If changing the inline script or style, recompute the corresponding SHA-256 CSP hash, run the check, and verify search, theme, anchors, and printing in a browser. Avoid `unsafe-inline` or broad external allowlists.

## Validation completed on the proposal

The security check passed. Browser checks confirmed that search, clearing search, and theme switching still work under the CSP, and all 12 chapters remain available. A search containing HTML was displayed literally without creating an image element. A temporary local probe containing an unauthorized inline script and an image request left the document title unchanged and made no image request to the local server. This probe was removed and is not part of the change. Printing and every browser/provider were not exhaustively retested.

## Separate application: unresolved, not verified here

The manual describes plaintext passwords, client-only login state, server CRUD without authorization, public-link Drive images, and CSV formula risks (baseline lines 211, 237, 260–272). The referenced application source and `API.gs` are **absent** from this repository, so those are documentation claims, not verified findings about a live backend.

Before using real student records, obtain the actual deployment/source and verify server-side identity and permission checks on every read/write/export, role enforcement independent of browser state, managed authentication instead of a plaintext password sheet, private image access, upload limits, and safe CSV export. Browser-side changes to this manual cannot repair the separate backend. Review existing exposed records/images and revoke public sharing where appropriate. An Apps Script URL is a public endpoint identifier, not by itself a secret or an authentication mechanism. [Apps Script execution and access settings](https://developers.google.com/apps-script/guides/web) must be reviewed alongside application authorization.

## Related repository findings

Public inventory found **653 repositories, 332 with Pages enabled**. Six related repositories were sampled for source review, in addition to this project. This is not an exhaustive audit of all deployed pages or dependencies.

| Priority | Repository and baseline evidence | Finding and safe action |
| --- | --- | --- |
| Urgent | [Trio_Telegram-Form-LIFF-Sheet](https://github.com/sanwithz/Trio_Telegram-Form-LIFF-Sheet/blob/b86fd63c053931436f616ab77f4ae6ddd7c9657d/index.html#L76), lines 76–119 and 150–234 | A bot credential is embedded in public HTML. Source posts contact/message/image and LINE identifiers to Telegram and Apps Script, with automatic LIFF login and no clear operator/destination notice. Treat the credential as compromised; revoke it through BotFather, pause collection, and migrate delivery to an authenticated server-side relay with clear notice/consent. No token was exercised, so present validity and misuse are unknown. Removing the source value does not revoke it or remove old history. |
| High review priority | [AccountBank](https://github.com/sanwithz/AccountBank/blob/5fca5fe2618cffc622170e0c795e719a9bcc0bbc/index.html#L14), lines 14–76 | A public KBank-branded credit/account mockup has no persistent on-page demo/unaffiliated label. No credential capture or working financial action was found. Remove real-bank branding, show a persistent fictional-demo notice, and disable action buttons, or unpublish the demo. |
| Review | [Root site](https://github.com/sanwithz/sanwithz.github.io/blob/99089b3/index.html#L17) | Root content is a full-page iframe of `https://www.sanwithz.com/`. A passive GET of that Blogger site found contact/search forms, an Apps Script iframe, advertising/Facebook embeds, and several CDN scripts including jQuery 1.11.1. No password field or redirect was found in its root HTML. These embedded resources need further review; no malicious behavior was established. Cross-origin isolation remains in place; the concern is the displayed content and its resource chain. |
| Lower | [LoginForm](https://github.com/sanwithz/LoginForm/tree/ca59c617), [sliding login template](https://github.com/sanwithz/javascript-sliding-login-and-registration-form/tree/672673a), [Login-Again](https://github.com/sanwithz/Login-Again/tree/2d22827b) | No exfiltration was found in these sampled sources. Generic credential-form demos should be clearly labeled and disabled for real credentials. The sliding template has same-page form submission, but its current inputs have no name attributes, so no credential-value transmission was established. Prefer non-submitting demo controls to prevent future accidental collection. |

All six sampled related Pages URLs returned HTTP 200. Source behavior and live reachability were checked separately; deployments were not all byte-compared. No real forms were submitted, bot/API credentials tested, backend records retrieved, or third-party collection endpoints invoked. A repository finding is not proof of Google's classifier cause or malicious intent.

Telegram documents that a bot token can be revoked through [BotFather](https://core.telegram.org/bots/tutorial). Rotate first; history cleanup alone is insufficient. LINE's official [login documentation](https://developers.line.biz/en/docs/line-login/integrate-line-login/) describes the profile scopes and authorization screen; platform authorization does not replace explaining the application's separate data destinations and purpose.

## Safe Browsing review steps

1. Open [Search Console](https://search.google.com/search-console/) in the owner's account. Add a URL-prefix property for `https://sanwithz.github.io/` to investigate all project paths, and optionally `https://sanwithz.github.io/Project-Guildance/` for this project. Include the trailing slash. Do not choose DNS/domain verification for `github.io`, which you do not control. [Property scope](https://support.google.com/webmasters/answer/10432366).
2. Verify the property using Google's exact HTML verification file or meta tag. For a root URL-prefix property, publish the supplied file in the root site's Pages source; for a project property, publish it at the property root, not only the deeper Thai directory. Keep verification in place. No verification token has been requested or installed by this audit. [Ownership verification](https://support.google.com/webmasters/answer/9008080?hl=en).
3. Open **Security & Manual Actions → Security issues**. Record each issue category, first-detected date, and every example URL. Samples are not exhaustive. Save the results privately; this report did not access the owner's Search Console.
4. Fix all reported categories and affected pages across the property. Prioritize credential revocation and pausing unsafe collection, then remove impersonation ambiguity and audit embedded/third-party content. Review the remaining Pages inventory using the report's evidence. Do not merely rename URLs, conceal behavior, or disable browser protection.
5. Merge the relevant reviewed fixes, wait for successful Pages deployments, then verify the public HTML matches the intended commit. Inspect mobile and desktop output, redirects, third-party requests, form destinations, and security policies. Confirm revoked secrets are no longer usable without publishing or exercising them in a public client. Do not claim deployment or token revocation based only on an open PR.
6. After every issue is fixed, choose **Request Review** in the Security issues report. Describe the issue, exact changes, deployed URLs/commits, and test results. Reviews may take days or weeks; do not resubmit while a request is pending. Google's [Security issues guidance](https://support.google.com/webmasters/answer/9044101?hl=en) is the source of truth for this workflow.
7. If the classification is erroneous after investigation, use Google's [incorrect-warning report](https://safebrowsing.google.com/safebrowsing/report_error/). Include the exact affected URL and evidence that the manual is passive. This is not a substitute for cleaning other flagged pages.
8. Recheck the public [site-status report](https://transparencyreport.google.com/safe-browsing/search?url=sanwithz.github.io), Search Console, and Safari after approval. Browser providers can differ; if Safari still warns after Google's clearance, inspect its warning details/provider and follow that provider's process. Keep Safari protection enabled. [Apple's guidance](https://support.apple.com/en-ca/guide/safari/sfri40697/mac).

### Review text to adapt only after deployment

> We investigated the deceptive-content warning affecting [exact URLs from Security issues]. We fixed [each reported issue] by [actual deployed changes, including any collection pause and credential revocation]. The scholarship URL is an offline manual with no sign-in, password collection, external code, or network submission. We added publisher/source attribution and a restrictive CSP. We verified [mobile/desktop results and deployed commit IDs] and checked the other affected URLs listed in the report. Please review the updated site.

Replace brackets with verified facts. Do not claim that unrelated repositories are fixed, a credential is revoked, or all 332 Pages sites are clean until confirmed. No review request has been submitted by this audit.
