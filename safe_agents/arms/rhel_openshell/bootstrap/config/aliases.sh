# Shell aliases for the interactive dev profile.
# Faithful snapshot from a development harness (config/aliases.sh).
# Sourced from ~/.bashrc.toolbox when SA_PROFILE=interactive.

# General
alias ll='ls -lah'
alias la='ls -A'
alias l='ls -CF'

# Claude Code
alias agents='list-claude-agents 2>/dev/null || echo "list-claude-agents not in PATH"'
alias agent-logs='ls -ltr ~/claude-agents/logs/'

# Tmux
alias tmux-list='tmux list-sessions'
alias ta='tmux attach -t'
alias tn='tmux new -s'

# Git
alias gs='git status'
alias gd='git diff'
alias ga='git add'
alias gc='git commit'
alias gp='git push'
alias gl='git log --oneline -20'

# Kubernetes/OpenShift (SA_PROFILE=interactive; installed by install-k8s-tools.sh)
alias k='kubectl'
alias kgp='kubectl get pods'
alias kgs='kubectl get svc'
alias kgd='kubectl get deployments'

# Python
alias py='python3'
alias venv='python3 -m venv'
alias activate='source .venv/bin/activate'

# Container
alias pd='podman'
alias pdi='podman images'
alias pdc='podman ps -a'
