# noesis_codebase_state

Review-only role. It is not referenced by any playbook in this repository.

Activation is refused unless `noesis_codebase_state_activate` is explicitly true.
Setting that variable is an operator action and is not granted by the presence of this role.

The collector itself lives in `noesis-agent-stack` at
`orchestration/codebase_state/`. This role, once approved, would install the
wrapper and a user crontab line for user `elvis` in `America/Denver`.

Do not run this role as part of a production play.
