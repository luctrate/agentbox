I've been building agentbox: Docker workers for Claude Code and Codex that appear as native sessions in Paseo.

The next iteration moves more policy outside the agents. An asp.now YAML catalog defines images, CLI versions, workspace access, networks, Vault-to-environment mappings and which workers each agent may launch. A trusted Python broker and host launcher enforce those choices. Isolated managers receive neither the Docker socket nor Vault access.

A useful workflow is manager → coding worker → research agent:

• The coding worker mounts only its project. Its network permits model/authentication endpoints and the scoped broker.
• The research agent gets public internet and a headless Playwright browser, with zero host bind mounts and no internal-service access.
• Workers stay visible in Paseo. Managers can send follow-ups and answer supported clarification questions without approving arbitrary tool execution.

Separate role authentication, pinned images, durable launch ownership and bounded delegation make the setup easier to reason about. The original simpler Docker workflow remains available too.

There are real limits: model credentials remain available to the agent using them, a manager can ask a credential-bearing worker to reveal a secret, and task messages can carry private data into public research. The host, Docker, Paseo and model gateway remain trusted. This is a personal-lab experiment, not a hostile multi-tenant platform.

Code, examples, installation guide, service templates and tests are published under MIT:
https://github.com/luctrate/agentbox

How are you separating project access, public research and tool credentials when coding agents delegate work?

#CodingAgents #ClaudeCode #Codex #Docker #Homelab
