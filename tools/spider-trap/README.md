# CareFortress Spider Trap

Cloudflare Worker that intercepts requests to known scanner/attacker paths
and returns an infinite maze of deterministically-generated links.

Based on the spider trap concept by John Strand / Black Hills Information Security.
Adapted for Cloudflare Workers (JavaScript).

See docs/CareFortress_Security_Test_Plan.md for Wazuh integration notes.
