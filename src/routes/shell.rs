//! Data every page layout needs: who's signed in and their form token.

use crate::auth::CurrentSession;

pub struct ShellUser {
    pub name: String,
    pub csrf: String,
}

#[derive(Default)]
pub struct Shell {
    pub user: Option<ShellUser>,
}

impl Shell {
    pub fn anonymous() -> Self {
        Self::default()
    }

    pub fn for_session(session: &CurrentSession) -> Self {
        Self {
            user: Some(ShellUser {
                name: session.0.user.name.clone(),
                csrf: session.0.csrf.clone(),
            }),
        }
    }
}
