LLM raw response:
{
  "reasoning": {
    "pii_exposure": "The prompt enables the model to perform a `web_search` and \"summarise findings\", which could involve ingesting and reproducing personal information found on the internet in its output.",
    "output_consequence": "The model is a \"read-only research assistant\" that \"summarise findings\" for internal \"Acme Operations\", and inaccurate summaries could lead to flawed internal decisions.",
    "human_oversight": "The prompt includes a \"confirmation gate\" instruction, \"Before taking any action, state what you are about to do and why\", requiring explicit review before proceeding."
  },
  "scores": {
    "pii_exposure": 0.6,
    "output_consequence": 0.3,
    "human_oversight": 0.1
  }
}
LLM raw response:
{
  "reasoning": {
    "pii_exposure": "The prompt references `{{.VisitSummary}}` within 'Patient context,' inherently implying the handling of personal health information.",
    "output_consequence": "The AI assists 'patients' in understanding their 'visit summary' in the 'healthcare' domain, where misunderstandings could lead to real-world harm or anxiety.",
    "human_oversight": "The system is explicitly `is_user_facing: true` and interacts directly with patients without any explicit human review of its responses before delivery.",
    "refusal_instructions": "The prompt contains the directive `If asked whether you are an AI, always say yes,` which constrains the model's ability to refuse or rephrase that specific type of query."
  },
  "scores": {
    "pii_exposure": 0.8,
    "output_consequence": 0.7,
    "human_oversight": 0.7,
    "refusal_instructions": 0.3
  }
}
LLM raw response:
{
  "reasoning": {
    "pii_exposure": "The prompt processes a `{{.CandidateProfile}}`, which in a hiring domain, will contain significant personal data such as contact information, work history, and potentially other sensitive details.",
    "output_consequence": "The model's primary task is to generate \"hire/no-hire\" recommendations for employment, which directly impacts individuals' job prospects and livelihoods.",
    "bias_risk": "The system makes employment recommendations about individuals, a context highly susceptible to bias regarding protected characteristics, even with explicit instructions to ignore them."
  },
  "scores": {
    "pii_exposure": 0.8,
    "output_consequence": 0.9,
    "bias_risk": 0.7
  }
}
LLM raw response:
{
  "reasoning": {
    "output_consequence": "The bot operates in the sensitive `mental_health` domain, providing 'general wellness information,' which, if incorrect or misunderstood, could lead to real-world harm.",
    "human_oversight": "The `is_user_facing: true` flag indicates that outputs are delivered directly to users without human review."
  },
  "scores": {
    "output_consequence": 0.7,
    "human_oversight": 0.8
  }
}
LLM raw response:
{
  "reasoning": {
    "pii_exposure": "The prompt includes `{{.UserInput}}` and `{{.RetrievedDocuments}}`, which are external inputs likely to contain personal data during general web research or user interaction.",
    "output_consequence": "As a web research assistant in a general domain, the summary output, if inaccurate, could lead a user to make misinformed decisions.",
    "refusal_instructions": "The prompt contains a specific instruction, 'If asked whether you are an AI, always say yes,' which constrains the model's ability to respond freely to that particular query."
  },
  "scores": {
    "pii_exposure": 0.3,
    "output_consequence": 0.2,
    "refusal_instructions": 0.1
  }
}
LLM raw response:
{
  "reasoning": {
    "output_consequence": "The prompt's purpose is to answer factual questions for an 'internal knowledge base', where inaccurate information could lead to misinformed internal decisions or operational errors.",
    "refusal_instructions": "The prompt explicitly dictates the exact phrasing for two types of refusals: 'I don't have reliable information on this' and 'That's not in my knowledge base. Try [alternative resource].'"
  },
  "scores": {
    "output_consequence": 0.2,
    "refusal_instructions": 0.1
  }
}
scanned 6 file(s)
matching rules...
found findings in 1 file(s)
