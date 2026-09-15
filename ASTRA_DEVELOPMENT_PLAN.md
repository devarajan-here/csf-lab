# GPT-6 Astra development plan

## Baseline and architectural decision

The inspected workspace was empty: there was no existing application, OpenAI SDK integration, model setting, or migration baseline. This implementation creates the requested offline Flask lab. GPT-6 Astra can develop and review it; the deployed room has no model dependency. Calling a hosted model from the room would violate its required offline architecture.

## Work plan and acceptance gates

1. **Preserve the product contract.** Maintain the three deployment inputs: `setup_vulnerabilities.sh`, `app.py`, and `templates/index.html`. Keep all 15 lessons, local assets, browser progress, target-host interpolation, server-side verification, and real target services. Additional documentation and tests are development artifacts.
2. **Implement deterministic lab evidence.** Generate short wordlists, an MD5 digest, PBKDF2/AES ciphertext, inert YARA controls, valid ICMP PCAP, real audit records, and an ext4 deleted-file image. Test that decryption, signatures, and carving yield the intended answers. Use explicit training-service behavior for the backdoor lesson; do not infer vulnerability from a banner.
3. **Validate the application contract.** Exercise all correct and incorrect answers, malformed input, unknown task IDs, oversized requests, denied and successful Burp forms, and public metadata. Ensure flags are not automatically serialized as answer fields. Run browser checks for every lesson, changing target addresses, progress persistence, hints, and responsive layouts.
4. **Validate a VM release.** Provision Ubuntu 24.04 on a host-only network and run each lesson from Kali. Confirm actual SSH password authentication, kernel audit recording, each listener's protocol, student commands, and artifact downloads. Reboot and verify automatic service recovery. Record the installed tool versions. This is a required release gate; Windows unit tests cannot establish it.
5. **Package offline delivery.** After installing all packages, remove temporary Internet access and export the target VM. Run the room and exercises again without network egress. Retain a clean snapshot for resets. Publish only after the VM gate succeeds.

## Astra usage during development

Use the exact model `gpt-6-astra` in any separately maintained API-based development harness. OpenAI's migration guidance requires the Responses API for tool calling. Replace previous `none` or `minimal` reasoning with `low`; otherwise preserve the effective effort. Remove unsupported `temperature`, `top_p`, and `top_logprobs` parameters. Remove Chat Completions `logprobs` and Responses `message.output_text.logprobs` includes where present. These are conditional future harness changes: this repository has none of those settings to migrate. [Official GPT-6 Astra migration guidance](https://developers.openai.com/api/docs/guides/latest-model)

When using a development harness, keep credentials on the developer machine, outside the lab artifacts and VM. Compare generated changes against the acceptance gates above. Require evidence for claims such as “all services work” and report which VM-dependent tests remain unrun. Avoid adding a model-based answer checker: deterministic checks are repeatable and work offline.

## Rollback

Keep source versions and a clean Ubuntu snapshot. Revert a source change and reprovision the lab when an exercise regresses. Revert the VM snapshot to remove installed accounts, audit watches, services, and generated data together. If a separate model-backed development harness is migrated later, retain its prior configuration and evaluation results for a harness-only rollback.
