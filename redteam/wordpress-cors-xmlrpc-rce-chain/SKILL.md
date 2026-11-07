---
name: wordpress-cors-xmlrpc-rce-chain
description: Use when verified WordPress CORS, XML-RPC, role, upload, and execution behaviors may form one authorized attack path.
version: 2.0.0
license: MIT
platforms: [linux, macos]
compatibility: Requires curl, a browser, and approved WordPress test identities
metadata:
  tags: [wordpress, cors, xmlrpc, chain, validation]
  category: redteam
  related_skills:
    - cross-attack-chains
    - hunt-cors
    - hunt-wordpress
    - triage-validation
    - xmlrpc-exploitation
---

# WordPress CORS, XML-RPC, and Upload Chain

This skill evaluates whether independently verified WordPress behaviors can
form a path to unauthorized file execution. It does not assume that CORS,
XML-RPC, registration, or an upload method is exploitable merely because it is
present.

## When to Use

- Credentialed CORS exposes non-public WordPress data.
- XML-RPC returns a protocol-valid method list.
- An approved test identity has an upload-capable role.
- A plugin or core upload operation may accept an executable file.
- The assessment explicitly permits state-changing upload and execution tests.

## Prerequisites

- Explicit authorization for each state-changing step.
- An approved synthetic account and test site or disposable content.
- Browser evidence for the CORS primitive.
- Protocol-valid XML-RPC evidence.
- Confirmed role capabilities and upload path.
- A benign test artifact and cleanup procedure.

## How to Run

Create an evidence matrix before sending a state-changing request:

```text
Primitive                 State       Evidence
Credentialed CORS         observed    browser reads approved non-public data
XML-RPC method            observed    protocol-valid methodResponse
Upload-capable identity   unverified  role and capability still required
Executable storage path   unverified  handler and server behavior required
Cleanup                   planned     test artifact and account removal
```

Stop when any prerequisite remains inferred.

## Procedure

### 1. Validate Credentialed CORS

Use `hunt-cors` to prove that an untrusted origin can read non-public data with
an approved browser session. Header reflection or public REST content is not
enough.

Record which information the primitive supplies to the next step. Usernames,
nonces, or plugin metadata have different security value and may not enable
authentication or upload.

### 2. Classify XML-RPC

```bash
TARGET="https://www.example.test"
OUTPUT_DIR="${OUTPUT_DIR:-./output/wordpress-chain}"
mkdir -p "$OUTPUT_DIR"

curl -sS --max-time 15 \
  -X POST "$TARGET/xmlrpc.php" \
  -H 'Content-Type: text/xml' \
  --data-binary \
  '<methodCall><methodName>system.listMethods</methodName></methodCall>' \
  -o "$OUTPUT_DIR/xmlrpc-methods.xml"
```

Require a valid `methodResponse`. Method presence does not establish that the
current identity may call it.

### 3. Verify the Approved Identity and Role

Use only the approved test identity. Confirm its current WordPress role and the
specific `upload_files` or plugin capability needed by the candidate operation.
Default subscriber registration usually does not provide upload capability.

Do not use password spraying or credentials obtained outside the assessment to
bridge a missing prerequisite.

### 4. Validate Upload Without Executing Code

When upload testing is explicitly authorized:

1. upload a uniquely named inert text or image file;
2. record the method, identity, response, media ID, and final URL;
3. verify the stored content and content type;
4. delete the artifact and record cleanup.

This demonstrates the upload boundary without introducing executable code.

### 5. Evaluate Execution Separately

File execution is a distinct prerequisite. Establish whether the upload
directory executes the relevant file type, whether extension or MIME validation
can be bypassed, and whether a plugin-specific handler moves the artifact.

Use a benign marker approved for the test environment. Do not deploy a command
shell. If execution cannot be demonstrated safely, report upload capability and
execution as separate observed and inferred states.

### 6. Assemble the Chain

```text
CORS read
  -> information required by approved test identity
  -> authorized XML-RPC or plugin operation
  -> inert upload accepted
  -> executable handling independently confirmed
  -> benign marker observed
  -> artifact removed
```

For every arrow, record why the previous step enables the next. Use
`cross-attack-chains` and `triage-validation` before assigning compound impact.

## Pitfalls

- Public REST user data may not supply credentials or a privileged identity.
- XML-RPC is a feature; method presence is not an authorization bypass.
- Subscriber and customer roles normally cannot upload arbitrary files.
- Upload acceptance does not prove executable storage.
- A plugin version match does not prove the vulnerable route and prerequisite.
- Combining several medium-confidence signals does not create a high-confidence
  chain.

## Verification

- CORS impact is reproduced in a browser with approved non-public data.
- XML-RPC evidence contains a protocol-valid response.
- The exact test identity and required capability are recorded.
- Upload validation uses an inert synthetic artifact and includes cleanup.
- Execution, when authorized, uses a benign marker in a disposable environment.
- Every chain step is confirmed independently; missing steps remain labeled
  inferred or not tested.
