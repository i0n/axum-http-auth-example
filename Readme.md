# A http auth server in Axum.

https://github.com/tokio-rs/axum

Intended as a reference implementation. Improvements and pull requests welcome.

to run:

    make docker-run-postgres
    make docker-run-redis
    cargo run

**NOTE!** You will need to run over https to test secure cookies.... 

## Database:
bb8
bb8-postgres
tokio-postgre

## Sessions:
axum-sessions
async-redis-session

## password hashing:
rust-argon2

## Templating:
askama

## Validation:
validator
