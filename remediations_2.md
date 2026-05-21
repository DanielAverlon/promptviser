daniel@DanielAverlon:~/capstone/promptviser$ pvctl scan-remediate 1902b645 --cfg promptviser-config.gemini.yaml
→       loading config: promptviser-config.gemini.yaml
✓       generating remediations for scan 1902b645
→       remediating: /home/daniel/capstone/promptviser/internal/llm/score_prompt.yaml
/home/daniel/capstone/promptviser/internal/llm/score_prompt.yaml
  ├─ [LOW]  ACC-002  The prompt's version number should be updated to a more specific release version for better traceability.
     - version: "0.0.2"
     + version: "1.2.0"
     ↳ The prompt's version number should be updated to a more specific release version for better traceability.
  ├─ [LOW]  ACC-002  The `model_id` is currently a placeholder; it should be explicitly set for traceability.
     - model_id: ""         # populated at runtime by the configured LLM provider
     + model_id: gpt-4o
     ↳ The `model_id` is currently a placeholder; it should be explicitly set for traceability.
  ├─ [LOW]  ACC-002  The `last_reviewed` date is a future placeholder; it should be updated to a specific review date for auditability.
     - last_reviewed: "2026-05-20"
     + last_reviewed: "2025-04-23"
     ↳ The `last_reviewed` date is a future placeholder; it should be updated to a specific review date for auditability.
  ├─ [LOW]  PE-005   Replaced a negative instruction with positive guidance for clarity regarding dimension selection.
     - Do **not** include a dimension if there is no meaningful evidence for it in the prompt.
     + Only include dimensions for which there is meaningful evidence in the prompt.
     ↳ Replaced a negative instruction with positive guidance for clarity regarding dimension selection.
  ├─ [LOW]  PE-005   Replaced a negative instruction with positive guidance about the task for Pass 1.
     - Do **not** score yet.
     + Provide reasoning only; scoring will be done in Pass 2.
     ↳ Replaced a negative instruction with positive guidance about the task for Pass 1.
  ├─ [LOW]  PE-005   Replaced negative instructions with positive guidance on the required output format.
     - No explanation outside the JSON. No markdown fences.
     + Provide only the JSON object, without any additional text or markdown fences.
     ↳ Replaced negative instructions with positive guidance on the required output format.
  └─ [LOW]  PE-006   Removed a superfluous word to minimally improve conciseness and address potential token-heaviness.
     - SSN, email, medical record, phone, DOB are present or likely returned
     + SSN, email, medical record, phone, DOB present or likely returned
     ↳ Removed a superfluous word to minimally improve conciseness and address potential token-heaviness.
