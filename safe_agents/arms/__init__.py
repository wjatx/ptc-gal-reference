"""safe_agents.arms — compute arm adapters for the safe-agents platform.

Each sub-package (ec2/, fargate/) is the thin adapter around run.sh that answers
two substrate questions per arms.md: where does the broker process sit, and how
is the agent's egress confined to it at the network layer?
"""
