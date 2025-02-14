use sqlx::FromRow;
use crate::adapter;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

#[allow(dead_code)]
#[cfg(any(feature = "postgres", feature = "mysql"))]
#[derive(Debug, FromRow)]
pub(crate) struct CasbinRule {
    pub id: i32,
    pub ptype: String,
    pub v0: String,
    pub v1: String,
    pub v2: String,
    pub v3: String,
    pub v4: String,
    pub v5: String,
}

#[allow(dead_code)]
#[cfg(feature = "sqlite")]
#[derive(Debug, FromRow)]
pub(crate) struct CasbinRule {
    pub id: i64,
    pub ptype: String,
    pub v0: String,
    pub v1: String,
    pub v2: String,
    pub v3: String,
    pub v4: String,
    pub v5: String,
}

#[derive(Debug)]
pub(crate) struct NewCasbinRule<'a> {
    pub ptype: &'a str,
    pub v0: &'a str,
    pub v1: &'a str,
    pub v2: &'a str,
    pub v3: &'a str,
    pub v4: &'a str,
    pub v5: &'a str,
}

#[derive(Clone)]
pub struct SqlxAdapter {
    pool: adapter::ConnectionPool,
    is_filtered: Arc<AtomicBool>,
    table_name: String,
}
