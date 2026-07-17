# Proposal: unify model "verified" determination across LLM model services

Status: draft / follow-up. Not for immediate merge — captures a refactor we
want to do after the surgical fix ships.

## Problem

`config_api/default_llm_model_service.py` determines the `verified` flag two
different ways for the two object kinds it returns:

- `_to_providers()` derives it from the discovery response:
  `name in models_response.verified_providers`.
- `_to_llm_models()` derives it from a **static SDK catalogue**
  (`_VERIFIED_MODEL_SET`, built from `openhands.sdk.llm.utils.verified_models`),
  **ignoring** `models_response.verified_models`.

So `ModelsResponse.verified_models` is populated by every service and consumed
by no one — effectively dead. The asymmetry is a real bug surface: on the
managed LiteLLM proxy (`LiteLLMProxyModelService`) every curated model is
declared verified via `verified_models`, but the dropdown still split them into
"Verified"/"Other" because the converter consulted the SDK list instead. Only
models whose bare name happened to coincide with the SDK list landed in
"Verified" — version-fragile and meaningless for an admin-curated catalogue.

## Shipped surgical fix (what exists today)

`#14774` added a proxy-scoped `_is_model_verified()` hook: the default returns
`model_name in _VERIFIED_MODEL_SET` (byte-identical for SaaS/OSS), and
`LiteLLMProxyModelService` overrides it to `name in verified_models`. This makes
the OHE dropdown a flat, header-less list without touching SaaS. It fixes the
symptom but keeps the asymmetry (and the override indirection).

## Proposed change

Make every `LLMModelService` populate `verified_models` with its full curated
verified set (as `provider/name`), then have `_to_llm_models()` consume
`verified_models` uniformly — mirroring how `_to_providers()` already uses
`verified_providers`. Remove the per-service `_is_model_verified` override and
the SDK-static special case; the default service's `verified_models` simply
becomes "the SDK catalogue."

## Why it's deferred (the blocker)

The SaaS model service currently populates `verified_models` with only the
`openhands/*` names, **not** the full Anthropic/OpenAI/Gemini verified set that
`_VERIFIED_MODEL_SET` covers. A blanket switch to `verified_models` would
de-verify those providers in cloud and change SaaS grouping. The unification
must first make the SaaS service populate `verified_models` with its full
verified set — a SaaS-touching change, out of scope for the surgical fix.

## Acceptance

- Provider and model `verified` determination share one code path.
- `ModelsResponse.verified_models` is consumed (no dead field).
- SaaS dropdown grouping is unchanged; OHE proxy dropdown stays flat.
