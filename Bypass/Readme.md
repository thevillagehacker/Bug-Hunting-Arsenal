## Are you familiar with zero-width space?

This character 👉 %E2%80%8B

Try inserting %E2%80%8B between characters of a blocked word. If the filter sees a different string, and the backend ignores the invisible character, you may bypass some filters.

Some string-contains filters don’t strip invisible Unicode before matching. The zero‑width space may break the pattern match without affecting backend processing.

Here’s what you can do:
> Identify a parameter that triggers a block (WAF, keyword filter).
> Insert %E2%80%8B between characters.
> Also test soft hyphen (%C2%AD), Unicode homoglyphs, and full‑width characters.

If the request succeeds, the issue here is in the input validation. It strips or catches only the exact banned string, but doesn’t normalize Unicode first.

> Source: https://x.com/0xacb/status/2079257935801188403?s=20
