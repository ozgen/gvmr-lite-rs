use std::collections::HashSet;

#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct AuthContext {
 pub subject: Option<String>,
 pub scopes: HashSet<String>,
 pub issuer: Option<String>,
 pub audience: Option<String>,
}
