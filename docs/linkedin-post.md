I've been experimenting with coding agents in my homelab, and kept coming back to a practical question: how do I give a worker the tools it needs without putting every task in my normal development environment?

I built agentbox: a small Docker wrapper for Claude Code and Codex, integrated with Paseo.

A manager agent can run:

agentbox spawn --detach codex "Review this project"

That starts a container worker which appears as a real Paseo session, with its transcript, tool activity, permission requests and parent link. Claude can delegate to Codex, and Codex can delegate to Claude.

Profiles select the image, mounted repositories, network, privilege and optional tool credentials. The images pin the agent CLI versions. Vault secrets are resolved on the host when a worker starts, rather than copied into prompts or static Paseo configuration.

A few details took more care than the Docker command itself: preserving both providers' native protocols, making Paseo's authenticated MCP endpoint reachable from containers, keeping worktrees valid, and cleaning up runtimes without losing session history.

This is a homelab experiment, not a hardened platform for untrusted agents. A manager with Docker access can bypass the profiles, and a worker can read credentials deliberately supplied to it. Network policy and temporary credential brokering are still separate problems.

I've published the scripts, images, setup guide and tests under MIT:
https://github.com/luctrate/agentbox

How are you handling tool access and credentials when coding agents delegate work?

#CodingAgents #ClaudeCode #Codex #Docker #Homelab
