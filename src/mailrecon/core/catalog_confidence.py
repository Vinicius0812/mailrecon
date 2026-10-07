"""Additional authored confidence/provenance messages, in canonical English and pt-BR."""

CATALOG = {
    "confidence.seed.reason": {
        "en": "Records investigator input, not independently verified identity.",
        "pt-br": "Registra os dados fornecidos pelo investigador, não uma identidade verificada de forma independente.",
    },
    "confidence.seed.label.name": {"en": "name", "pt-br": "nome"},
    "confidence.seed.label.email": {"en": "email", "pt-br": "e-mail"},
    "confidence.seed.label.username": {"en": "username", "pt-br": "nome de usuário"},
    "confidence.seed.label.domain": {"en": "domain", "pt-br": "domínio"},
    "confidence.seed.label.organization": {"en": "organization", "pt-br": "organização"},
    "confidence.seed.label.context": {"en": "context", "pt-br": "contexto"},
    "confidence.candidate.summary": {
        "en": "{email} was classified as {status} from {source}.",
        "pt-br": "{email} foi classificado como {status}, com origem em {source}.",
    },
    "confidence.dns.limitation": {
        "en": "DNS describes domain infrastructure and does not confirm individual mailbox existence. DNS observations do not establish identity ownership.",
        "pt-br": "O DNS descreve a infraestrutura do domínio e não confirma a existência de uma caixa de correio individual. Observações DNS não comprovam a titularidade de uma identidade.",
    },
    "confidence.notes.join": {"en": "{first}; {next}", "pt-br": "{first}; {next}"},
    "confidence.profile.synthetic_summary": {
        "en": "Simulated public profile check for {platform}/{handle} returned status {status}.",
        "pt-br": "A verificação simulada do perfil público de {platform}/{handle} retornou o status {status}.",
    },
    "confidence.profile.synthetic_limitation": {
        "en": "Synthetic lab result; no public HTTP observation was collected.",
        "pt-br": "Resultado sintético de laboratório; nenhuma observação HTTP pública foi coletada.",
    },
    "confidence.profile.observations": {
        "en": "http_status={http_status}, final_url={final_url}",
        "pt-br": "http_status={http_status}, final_url={final_url}",
    },
}
