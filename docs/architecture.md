# AuthTrail Architecture

AuthTrail is a local-first OpenSSH authentication log analyzer. The production build is a static export, and log contents remain in the browser.

## Data flow

```text
User input (.log/.txt or paste)
        |
        v
      ingest
  validate / split / dedupe
        |
        v
      parse
 normalized AuthEvent records
        |
        v
    chronology
 relative ordering + confidence
        |
        v
    correlate
 observations -> confirmed attempts
        |
        +-------------------+
        |                   |
        v                   v
      detect              stats
      R1-R5           summaries/tables
        |                   |
        +---------+---------+
                  |
                  v
               render
       findings / evidence / events
```

## Boundaries

### `src/lib/`
Pure TypeScript analysis core with no React dependency.

- `ingest.ts`: input validation, line numbering, duplicate policy
- `timestamp.ts`: timestamp parsing and chronology confidence
- `parse.ts`: OpenSSH line parsing and source-address normalization
- `correlate.ts`: observation-to-attempt correlation
- `detect.ts`: deterministic rules R1-R5 and causal evidence selection
- `stats.ts`: summary and ranking statistics
- `analyze.ts`: analysis facade
- `types.ts`: normalized contracts

### `src/components/`
React presentation layer. It receives analysis output and never performs server-side log processing.

### `tests/`
Behavioral, regression, UI, accessibility, and adversarial performance tests.

## Security and privacy model

- No server-side log processing
- No telemetry or analytics
- No network lookups or IP reputation services
- No persistence of uploaded logs
- No `dangerouslySetInnerHTML`
- Untrusted log contents are rendered as escaped React text
- Time-dependent detections suppress when chronology is not trustworthy
- Uncertain observations do not become detection-bearing attempts

## Detection philosophy

AuthTrail describes observed behavior rather than declaring an address malicious. When evidence is ambiguous, the implementation prefers under-reporting to fabricated certainty.
