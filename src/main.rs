use argon2::{self, Config};
use askama::Template;
use async_redis_session::RedisSessionStore;
use axum::{
    async_trait,
    error_handling::HandleErrorLayer,
    extract::{rejection::FormRejection, Form, FromRef, FromRequest, FromRequestParts, State},
    http::{request::Parts, Request, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, get_service},
    Router,
};
use axum_sessions::{
    extractors::{ReadableSession, WritableSession},
    SessionLayer,
};
use bb8::{Pool, PooledConnection};
use bb8_postgres::PostgresConnectionManager;
use rand::Rng;
use serde::{de::DeserializeOwned, Deserialize};
use std::{io, net::SocketAddr, time::Duration};
use thiserror::Error;
use tokio::signal;
use tokio_postgres::NoTls;
use tower::{BoxError, ServiceBuilder};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use validator::Validate;

// Types /////////////////////////////

type ConnectionPool = Pool<PostgresConnectionManager<NoTls>>;

// Structs //////////////////////////

#[derive(Deserialize, Debug)]
struct AppConfig {
    #[serde(default = "default_environment")]
    environment: String,
    #[serde(default = "default_log_level")]
    log_level: String,
    #[serde(default = "default_postgres_host")]
    postgres_host: String,
    #[serde(default = "default_postgres_port")]
    postgres_port: String,
    #[serde(default = "default_postgres_db")]
    postgres_db: String,
    #[serde(default = "default_postgres_user")]
    postgres_user: String,
    #[serde(default = "default_postgres_password")]
    postgres_password: String,
    #[serde(default = "default_redis_host")]
    redis_host: String,
    #[serde(default = "default_redis_port")]
    redis_port: String,
}

struct DatabaseConnection(PooledConnection<'static, PostgresConnectionManager<NoTls>>);

struct HtmlTemplate<T>(T);

#[derive(Debug, Deserialize, Validate)]
pub struct CreateSignupInput {
    #[validate(email)]
    pub email: String,
    #[validate(must_match = "confirm_password")]
    #[validate(length(min = 6))]
    pub password: String,
    #[validate(must_match(other = "confirm_password"))]
    pub confirm_password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateLoginInput {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 6))]
    pub password: String,
}

// Templates //

#[derive(Template)]
#[template(path = "account.html")]
struct AccountTemplate {
    title: String,
    email: String,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    title: String,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    title: String,
    errors: validator::ValidationErrors,
}

#[derive(Template)]
#[template(path = "signup.html")]
struct SignupTemplate {
    title: String,
    errors: validator::ValidationErrors,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ValidatedSignupForm<T>(pub T);

#[derive(Debug, Clone, Copy, Default)]
pub struct ValidatedLoginForm<T>(pub T);

// enums ////////////////////////////////////

#[derive(Debug, Error)]
pub enum SignupFormError {
    #[error(transparent)]
    ValidationError(#[from] validator::ValidationErrors),

    #[error(transparent)]
    AxumFormRejection(#[from] FormRejection),
}

#[derive(Debug, Error)]
pub enum LoginFormError {
    #[error(transparent)]
    ValidationError(#[from] validator::ValidationErrors),

    #[error(transparent)]
    AxumFormRejection(#[from] FormRejection),
}

// Traits ///////////////////////////////////////////

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template. Error: {}", err),
            )
                .into_response(),
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for DatabaseConnection
where
    ConnectionPool: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let pool = ConnectionPool::from_ref(state);

        let conn = pool.get_owned().await.map_err(internal_error)?;
        tracing::debug!("{:#?}", conn);
        Ok(Self(conn))
    }
}

#[async_trait]
impl<T, S, B> FromRequest<S, B> for ValidatedSignupForm<T>
where
    T: DeserializeOwned + Validate,
    S: Send + Sync,
    Form<T>: FromRequest<S, B, Rejection = FormRejection>,
    B: Send + 'static,
{
    type Rejection = SignupFormError;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        let Form(value) = Form::<T>::from_request(req, state).await?;
        value.validate()?;
        Ok(ValidatedSignupForm(value))
    }
}

#[async_trait]
impl<T, S, B> FromRequest<S, B> for ValidatedLoginForm<T>
where
    T: DeserializeOwned + Validate,
    S: Send + Sync,
    Form<T>: FromRequest<S, B, Rejection = FormRejection>,
    B: Send + 'static,
{
    type Rejection = LoginFormError;

    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        let Form(value) = Form::<T>::from_request(req, state).await?;
        value.validate()?;
        Ok(ValidatedLoginForm(value))
    }
}

impl IntoResponse for SignupFormError {
    fn into_response(self) -> Response {
        match self {
            SignupFormError::ValidationError(v) => {
                let template = SignupTemplate {
                    title: "App - Signup|Error".to_string(),
                    errors: v,
                };
                (StatusCode::BAD_REQUEST, HtmlTemplate(template))
            }
            SignupFormError::AxumFormRejection(_) => {
                let empty_errors = validator::ValidationErrors::new();
                let template = SignupTemplate {
                    title: "App - Signup|Error".to_string(),
                    errors: empty_errors,
                };
                (StatusCode::BAD_REQUEST, HtmlTemplate(template))
            }
        }
        .into_response()
    }
}

impl IntoResponse for LoginFormError {
    fn into_response(self) -> Response {
        match self {
            LoginFormError::ValidationError(v) => {
                let template = LoginTemplate {
                    title: "App - Login|Error".to_string(),
                    errors: v,
                };
                (StatusCode::BAD_REQUEST, HtmlTemplate(template))
            }
            LoginFormError::AxumFormRejection(_) => {
                let empty_errors = validator::ValidationErrors::new();
                let template = LoginTemplate {
                    title: "App - Login|Error".to_string(),
                    errors: empty_errors,
                };
                (StatusCode::BAD_REQUEST, HtmlTemplate(template))
            }
        }
        .into_response()
    }
}

// Main /////////////////////////////

const SALT: &str = "salt_goes_here";

#[tokio::main]
async fn main() {
    match envy::from_env::<AppConfig>() {
        Ok(config) => {
            tracing_subscriber::registry()
                .with(tracing_subscriber::EnvFilter::new(&config.log_level))
                .with(tracing_subscriber::fmt::layer())
                .init();
            tracing::debug!("ENVIRONMENT: {:#?}", config.environment);
            tracing::debug!("LOG_LEVEL: {:#?}", config.log_level);
            tracing::debug!("POSTGRES_HOST: {:#?}", config.postgres_host);
            tracing::debug!("POSTGRES_PORT: {:#?}", config.postgres_port);
            tracing::debug!("POSTGRES_DB: {:#?}", config.postgres_db);
            tracing::debug!("POSTGRES_USER: {:#?}", config.postgres_user);
            tracing::debug!("REDIS_HOST: {:#?}", config.redis_host);
            tracing::debug!("REDIS_PORT: {:#?}", config.redis_port);

            let store = RedisSessionStore::new(format!(
                "redis://{}:{}/",
                config.redis_host, config.redis_port,
            ))
            .unwrap();
            let secret = rand::thread_rng().gen::<[u8; 128]>();
            let session_layer = SessionLayer::new(store, &secret);

            let connection_string = format!(
                "host={} port={} user={} password={} dbname={} connect_timeout=10",
                config.postgres_host,
                config.postgres_port,
                config.postgres_user,
                config.postgres_password,
                config.postgres_db,
            );
            let manager =
                PostgresConnectionManager::new_from_stringlike(connection_string, NoTls).unwrap();

            let pool = Pool::builder().max_size(30).build(manager).await.unwrap();

            let app = Router::new()
                .route("/", get(handle_root))
                .route("/signup", get(handle_signup).post(handle_create_signup))
                .route("/login", get(handle_login).post(handle_create_login))
                .route("/logout", get(handle_logout))
                .route("/account", get(handle_account_protected))
                .nest_service(
                    "/public",
                    get_service(ServeDir::new("public")).handle_error(handle_error),
                )
                // Add middleware to all routes
                .layer(session_layer)
                .layer(
                    ServiceBuilder::new()
                        .layer(HandleErrorLayer::new(|error: BoxError| async move {
                            if error.is::<tower::timeout::error::Elapsed>() {
                                Ok(StatusCode::REQUEST_TIMEOUT)
                            } else {
                                Err((
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    format!("Unhandled internal error: {}", error),
                                ))
                            }
                        }))
                        .timeout(Duration::from_secs(10))
                        .layer(TraceLayer::new_for_http())
                        .into_inner(),
                )
                .with_state(pool);

            let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
            tracing::debug!("listening on {}", addr);
            if config.environment == "production" {
                axum::Server::bind(&addr)
                    .serve(app.into_make_service())
                    .with_graceful_shutdown(shutdown_signal())
                    .await
                    .unwrap();
            } else {
                axum::Server::bind(&addr)
                    .serve(app.into_make_service())
                    .await
                    .unwrap();
            }
        }
        Err(error) => panic!("{:#?}", error),
    }
}

// Route Handlers ////////////////////////////////

async fn handle_root() -> impl IntoResponse {
    let template = IndexTemplate {
        title: "App".to_string(),
    };
    HtmlTemplate(template)
}

async fn handle_login() -> impl IntoResponse {
    let template = LoginTemplate {
        title: "App - Login".to_string(),
        errors: validator::ValidationErrors::new(),
    };
    HtmlTemplate(template)
}

async fn handle_signup() -> impl IntoResponse {
    let template = SignupTemplate {
        title: "App - Signup".to_string(),
        errors: validator::ValidationErrors::new(),
    };
    HtmlTemplate(template)
}

async fn handle_create_login(
    State(pool): State<ConnectionPool>,
    mut session: WritableSession,
    ValidatedLoginForm(input): ValidatedLoginForm<CreateLoginInput>,
) -> impl IntoResponse {
    let config = Config::default();
    let hash = argon2::hash_encoded(input.password.as_bytes(), SALT.as_bytes(), &config).unwrap();
    let conn = pool.get().await.map_err(internal_error).unwrap();
    let query = conn
        .query_one(
            "select * FROM accounts where active = true AND email = $1 AND password = $2 LIMIT 1",
            &[&input.email, &hash],
        )
        .await;
    match query {
        Ok(_) => {
            session
                .insert("email", input.email)
                .expect("Session could not be created.");
            Redirect::to("/account").into_response()
        }
        Err(_) => {
            let p = validator::ValidationError::new("password");
            let mut vs = validator::ValidationErrors::new();
            vs.add("password", p);
            let template = LoginTemplate {
                title: "App - Login|Error".to_string(),
                errors: vs,
            };
            HtmlTemplate(template).into_response()
        }
    }
}

async fn handle_create_signup(
    State(pool): State<ConnectionPool>,
    mut session: WritableSession,
    ValidatedSignupForm(input): ValidatedSignupForm<CreateSignupInput>,
) -> impl IntoResponse {
    let config = Config::default();
    let hash = argon2::hash_encoded(input.password.as_bytes(), SALT.as_bytes(), &config).unwrap();
    let conn = pool.get().await.map_err(internal_error).unwrap();
    let query = conn
        .execute(
            "INSERT into accounts (email, password) VALUES($1,$2)",
            &[&input.email, &hash],
        )
        .await;
    match query {
        Ok(_) => {
            session
                .insert("email", input.email)
                .expect("Session could not be created.");
            Redirect::to("/account").into_response()
        }
        Err(_) => {
            let p = validator::ValidationError::new("password");
            let mut vs = validator::ValidationErrors::new();
            vs.add("password", p);
            let template = SignupTemplate {
                title: "App - Signup|Error".to_string(),
                errors: vs,
            };
            HtmlTemplate(template).into_response()
        }
    }
}

async fn handle_logout(mut session: WritableSession) -> impl IntoResponse {
    session.destroy();
    Redirect::to("/")
}

async fn handle_account_protected(session: ReadableSession) -> impl IntoResponse {
    let email = session
        .get::<String>("email")
        .map_or(String::from(""), |s| s);

    if email != "" {
        let authed_template = AccountTemplate {
            title: "App - Account".to_string(),
            email: format!("{}", email),
        };
        HtmlTemplate(authed_template).into_response()
    } else {
        Redirect::to("/login").into_response()
    }
}

async fn handle_error(_err: io::Error) -> impl IntoResponse {
    (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong...")
}

// Utility Functions ////////////////////////////////

/// for mapping any error into a `500 Internal Server Error` response.
fn internal_error<E>(err: E) -> (StatusCode, String)
where
    E: std::error::Error,
{
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

// Config functions //////////////////////////////

fn default_environment() -> String {
    String::from("development")
}

fn default_log_level() -> String {
    String::from("debug")
}

fn default_postgres_host() -> String {
    String::from("0.0.0.0")
}

fn default_postgres_port() -> String {
    String::from("5432")
}

fn default_postgres_db() -> String {
    String::from("axum-http-auth-example")
}

fn default_postgres_user() -> String {
    String::from("postgres")
}

fn default_postgres_password() -> String {
    String::from("password")
}

fn default_redis_host() -> String {
    String::from("0.0.0.0")
}

fn default_redis_port() -> String {
    String::from("6379")
}

// Graceful shutdown //////////////////////////////////

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    //#[cfg(not(unix))]
    //let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::debug!("signal received, starting graceful shutdown");
}
