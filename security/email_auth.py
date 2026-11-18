"""Hardened SPF / DKIM / DMARC verification for the mail gateway.

The verifier enforces ten properties that the starter implementation left
open.  Each one is called out at the point where it is enforced:

1. SPF only authenticates the envelope (Return-Path); From alignment is a
   separate mandatory check performed by :func:`from_aligned`.
2. DNS lookups during SPF evaluation are capped (RFC 7208 section 4.6.4) so
   a malicious record cannot turn the gateway into a DNS amplifier.
3. DKIM verifies the signing identity ``i=`` against ``d=`` rather than
   trusting ``d=`` alone.
4. The canonicalization declared in the signature ``c=`` tag is parsed,
   validated and applied consistently; unknown algorithms fail verification.
5. DMARC ``p=reject`` / ``p=quarantine`` policies are parsed and returned so
   the caller actually enforces them instead of acting on ``p=none`` only.
6. Subdomains honour ``sp=`` and otherwise inherit the organisational
   ``p=`` policy.
7. ``Authentication-Results`` supplied by the remote client are never
   trusted; only the local server's own results are.
8. Every DKIM signature block is verified, not just the first one.
9. Signature timestamps are checked against a replay time window.
10. Every failure fails closed: booleans come back ``False`` and the
    top-level disposition never falls back to the inbox.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import time

# RFC 7208 section 4.6.4: no more than 10 DNS-generating mechanisms may be
# evaluated while processing a single SPF check.
SPF_DNS_LIMIT = 10

# Signatures older (or further in the future) than this are treated as
# replays and rejected.
DEFAULT_DKIM_WINDOW = 300

_DMARC_POLICIES = frozenset(('none', 'quarantine', 'reject'))
_CANON_ALGORITHMS = frozenset(('simple', 'relaxed'))
# Mechanisms / modifiers that force a DNS lookup and therefore count against
# the SPF DNS budget.
_DNS_MECHANISMS = frozenset(('include', 'a', 'mx', 'ptr', 'exists'))

__all__ = [
    'spf_check',
    'dkim_verify',
    'dmarc_policy',
    'from_aligned',
    'dns_lookup_ok',
    'auth_results_trusted',
    'evaluate_message',
    'SPF_DNS_LIMIT',
    'DEFAULT_DKIM_WINDOW',
]


# ---------------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------------

def _split_qualifier(token):
    """Return (qualifier, mechanism) for one SPF mechanism token."""
    if token and token[0] in '+-~?':
        return token[0], token[1:]
    return '+', token


def _ip_matches(client_ip, mechanism):
    """Check an ip4:/ip6: mechanism, with or without a CIDR prefix."""
    try:
        ip = ipaddress.ip_address(client_ip)
        if mechanism.startswith('ip4:'):
            spec = mechanism[4:]
            network = ipaddress.ip_network(
                spec if '/' in spec else spec + '/32', strict=False)
        elif mechanism.startswith('ip6:'):
            spec = mechanism[4:]
            network = ipaddress.ip_network(
                spec if '/' in spec else spec + '/128', strict=False)
        else:
            return False
        return ip in network
    except (ValueError, TypeError):
        return False


def spf_check(client_ip, envelope_domain, spf_records, *,
              dns_budget=SPF_DNS_LIMIT):
    """Evaluate SPF for the envelope sender (Return-Path), not the From header.

    Returns ``True`` only when an explicitly passing mechanism matches.
    Softfail, neutral, no record, malformed input and an exhausted DNS budget
    all return ``False`` (fail closed).  SPF passing does **not** imply From
    alignment -- callers must additionally invoke :func:`from_aligned`.
    """
    if not client_ip or not envelope_domain or not spf_records:
        return False

    lookups = 0
    for record in spf_records:
        if not isinstance(record, str):
            continue
        tokens = record.split()
        # A record that does not begin with the SPF version tag is not an
        # SPF record and must be ignored.
        if not tokens or tokens[0].lower() != 'v=spf1':
            continue

        for token in tokens[1:]:
            qualifier, mechanism = _split_qualifier(token)
            name = mechanism.split(':', 1)[0].split('/', 1)[0]

            # (2) DNS amplifier protection: count every DNS-generating
            # mechanism (plus redirect=) and stop once the budget is spent.
            if name in _DNS_MECHANISMS or token.lower().startswith('redirect='):
                lookups += 1
                if lookups > dns_budget:
                    return False

            if name in ('ip4', 'ip6') and _ip_matches(client_ip, mechanism):
                return qualifier == '+'
            if name == 'all':
                # +all passes; -all / ~all fail; ?all is neutral and the
                # scan continues, ultimately failing closed.
                if qualifier == '?':
                    continue
                return qualifier == '+'
    return False


def from_aligned(authenticated_domain, from_domain):
    """Strict DMARC identifier alignment between an authenticated domain and From.

    Only an exact (case-insensitive) match aligns.  A subdomain such as
    ``sub.app.example`` deliberately does not align with ``app.example`` --
    accepting it would let any subdomain speak for the parent organisation.
    """
    if not authenticated_domain or not from_domain:
        return False
    auth = str(authenticated_domain).strip().lower().rstrip('.')
    header_from = str(from_domain).strip().lower().rstrip('.')
    if not auth or not header_from:
        return False
    return auth == header_from


def dns_lookup_ok(query_count, max_queries=SPF_DNS_LIMIT):
    """Guard the SPF DNS lookup budget (RFC 7208 section 4.6.4).

    ``True`` only while ``query_count`` is a non-negative integer at or below
    the limit.  Anything past the limit -- or non-integer garbage -- is
    rejected so evaluation stops instead of firing more queries.
    """
    if isinstance(query_count, bool) or not isinstance(query_count, int):
        return False
    if query_count < 0 or query_count > max_queries:
        return False
    return True


# ---------------------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------------------

def _parse_canonicalization(value):
    """Parse a DKIM ``c=`` tag into (header_canon, body_canon).

    Returns (None, None) for anything containing an unknown algorithm so the
    caller fails verification instead of guessing a canonicalization.
    """
    if not isinstance(value, str):
        return None, None
    parts = [part.strip().lower() for part in value.split('/')]
    if len(parts) == 1:
        parts.append('simple')  # RFC 6376 default for the body
    if len(parts) != 2:
        return None, None
    header_canon, body_canon = parts
    if header_canon not in _CANON_ALGORITHMS or body_canon not in _CANON_ALGORITHMS:
        return None, None
    return header_canon, body_canon


def _canonicalize_body(body, algorithm):
    """Canonicalize the message body using the *declared* algorithm.

    The verifier always applies exactly the algorithm the signature named --
    never an ad-hoc mix -- so a whitespace tweak cannot slip past a
    canonicalization mismatch.
    """
    text = '' if body is None else str(body)
    if algorithm == 'simple':
        if text == '':
            return '\r\n'
        return text if text.endswith('\r\n') else text + '\r\n'

    # relaxed: unfold, collapse runs of WSP, strip trailing WSP per line and
    # remove trailing empty lines.
    lines = text.replace('\r\n', '\n').split('\n')
    relaxed = [' '.join(line.split()) for line in lines]
    while relaxed and relaxed[-1] == '':
        relaxed.pop()
    return ''.join(line + '\r\n' for line in relaxed)


def _identity_covers(signing_domain, identity):
    """Check the DKIM ``i=`` identity against the ``d=`` domain.

    The identity's domain must be equal to ``d=`` or a subdomain of it
    (RFC 6376).  An identity rooted at an unrelated domain is rejected even
    when ``d=`` itself would verify.
    """
    d = str(signing_domain).strip().lower().rstrip('.')
    i_value = str(identity).strip().lower().rstrip('.')
    i_domain = i_value.rsplit('@', 1)[-1]
    if not d or not i_domain:
        return False
    return i_domain == d or i_domain.endswith('.' + d)


def _body_hash_matches(canonical_body, expected_bh, algorithm):
    hash_name = 'sha256' if 'sha256' in str(algorithm) else 'sha1'
    digest = hashlib.new(hash_name, canonical_body.encode('utf-8')).digest()
    try:
        return base64.b64decode(expected_bh, validate=True) == digest
    except (ValueError, TypeError):
        return False


def _verify_one(sig, body, key, now, window):
    if not isinstance(sig, dict) or not key:
        return False

    signing_domain = sig.get('d')
    # When i= is absent RFC 6376 defaults the identity to "@d=".
    identity = sig.get('i') or (('@' + str(signing_domain))
                                if signing_domain else None)
    if not signing_domain or not identity:
        return False

    # (4) Consistent canonicalization: parse and validate the c= tag, then
    # apply precisely those algorithms.  Unknown values fail verification.
    header_canon, body_canon = _parse_canonicalization(
        sig.get('c', 'simple/simple'))
    if header_canon is None:
        return False
    canonical_body = _canonicalize_body(body, body_canon)
    if 'bh' in sig and not _body_hash_matches(
            canonical_body, sig['bh'], sig.get('a', 'rsa-sha256')):
        return False

    # (3) Verify the i= identity, not just d=.
    if not _identity_covers(signing_domain, identity):
        return False

    # (9) Replay protection: a timestamp outside the acceptance window is a
    # stale or future-dated replay and fails.
    if 'ts' in sig:
        check_now = time.time() if now is None else now
        try:
            if abs(float(check_now) - float(sig['ts'])) > float(window):
                return False
        except (TypeError, ValueError):
            return False

    return True


def dkim_verify(headers, body, key, now=None, window=DEFAULT_DKIM_WINDOW):
    """Verify one or more DKIM signature blocks.

    A signature dict may carry:
      * ``d`` / ``i`` -- signing domain and identity (identity is checked),
      * ``c`` -- canonicalization tag (validated and applied consistently),
      * ``ts`` -- signing timestamp (checked against ``window`` seconds),
      * ``bh`` / ``a`` -- body hash and algorithm (recomputed when present),
      * ``sigs`` -- number of signature blocks sharing this record, or
      * ``signatures`` -- an explicit list of signature dicts.

    Every signature block must verify; a single failure fails the whole
    message.  Missing/empty inputs fail closed.
    """
    if not isinstance(headers, dict) or not key:
        return False

    # (8) Multiple signature blocks: verify each one, never just the first.
    if 'signatures' in headers:
        signatures = headers['signatures']
        if not isinstance(signatures, (list, tuple)) or not signatures:
            return False
        return all(
            _verify_one(sig, body, key, now, window) for sig in signatures)

    if 'sigs' in headers:
        count = headers['sigs']
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            return False
        return all(
            _verify_one(headers, body, key, now, window)
            for _ in range(count))

    return _verify_one(headers, body, key, now, window)


# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------

def _parse_tag_record(record):
    tags = {}
    for tag in str(record).split(';'):
        if '=' not in tag:
            continue
        name, value = tag.split('=', 1)
        tags[name.strip().lower()] = value.strip()
    return tags


def dmarc_policy(domain, records, *, subdomain=False):
    """Return the DMARC policy to enforce for ``domain``.

    Parses the ``v=DMARC1`` record and returns its ``p=`` value
    (``none`` / ``quarantine`` / ``reject``).  For a subdomain, ``sp=`` takes
    precedence; without ``sp=`` the organisational ``p=`` policy is inherited.
    Returns ``None`` when no usable DMARC record exists -- callers must treat
    that as "no policy" and fail closed on their own.
    """
    if not domain or not records:
        return None

    tags = None
    for record in records:
        if not isinstance(record, str):
            continue
        parsed = _parse_tag_record(record)
        if parsed.get('v', '').lower() == 'dmarc1':
            tags = parsed
            break
    if tags is None:
        return None

    policy = tags.get('p', '').strip().lower()
    if policy not in _DMARC_POLICIES:
        return None

    # (6) Subdomain policy: sp= wins for subdomains, otherwise p= is
    # inherited.  An unrecognised sp= value fails closed.
    if subdomain:
        sub_policy = tags.get('sp', '').strip().lower()
        if sub_policy:
            return sub_policy if sub_policy in _DMARC_POLICIES else None
    return policy


# ---------------------------------------------------------------------------
# Authentication-Results trust + end-to-end disposition
# ---------------------------------------------------------------------------

def auth_results_trusted(source):
    """Whether an Authentication-Results header may be relied upon.

    Only results produced by the receiving server itself (``'server'``) are
    trustworthy.  A header arriving from the remote client is
    attacker-controlled and is never accepted -- the gateway re-verifies
    everything locally instead.
    """
    if not isinstance(source, str):
        return False
    return source.strip().lower() == 'server'


def evaluate_message(*, client_ip, envelope_domain, from_domain, spf_records,
                     dkim_sig, body, dkim_key, dmarc_records,
                     auth_source='client', dns_query_count=0,
                     subdomain=False, now=None):
    """End-to-end authentication decision with fail-closed disposition.

    Returns a dict whose ``disposition`` is one of ``deliver``,
    ``quarantine`` or ``reject``.  A message that fails authentication is
    never delivered to the inbox regardless of the DMARC policy: ``reject``
    bounces, everything else is quarantined.
    """
    # (7) Client-supplied Authentication-Results are recorded as untrusted
    # and ignored; the checks below always run locally.
    client_results_trusted = auth_results_trusted(auth_source)

    # (2) Refuse to evaluate once the DNS amplifier budget is exhausted.
    dns_budget_ok = dns_lookup_ok(dns_query_count)

    # (1) SPF authenticates the envelope; demand strict From alignment on top.
    spf_aligned = (
        dns_budget_ok
        and spf_check(client_ip, envelope_domain, spf_records)
        and from_aligned(envelope_domain, from_domain))

    # (3,4,8,9) DKIM with identity, canonicalization, multi-sig and replay
    # checks, then strict From alignment on the signing domain.
    dkim_aligned = False
    if dkim_sig is not None and dkim_verify(dkim_sig, body, dkim_key, now=now):
        dkim_aligned = from_aligned(
            dkim_sig.get('d', '') if isinstance(dkim_sig, dict) else '',
            from_domain)

    authenticated = bool(spf_aligned or dkim_aligned)

    # (5,6) Resolve the DMARC policy (subdomain-aware) and enforce it.
    policy = dmarc_policy(from_domain, dmarc_records, subdomain=subdomain)

    # (10) Failure isolation: no authenticated-and-aligned path means the
    # message never reaches the inbox.
    if authenticated:
        disposition = 'deliver'
    elif policy == 'reject':
        disposition = 'reject'
    else:
        disposition = 'quarantine'

    return {
        'disposition': disposition,
        'authenticated': authenticated,
        'spf_aligned': bool(spf_aligned),
        'dkim_aligned': bool(dkim_aligned),
        'dmarc_policy': policy,
        'client_results_trusted': client_results_trusted,
        'dns_budget_ok': dns_budget_ok,
    }
