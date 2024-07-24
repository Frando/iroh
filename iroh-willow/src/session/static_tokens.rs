use std::{
    cell::RefCell,
    future::poll_fn,
    rc::Rc,
    task::{ready, Poll},
};

use crate::{
    proto::{
        sync::{DynamicToken, SetupBindStaticToken, StaticToken, StaticTokenHandle},
        willow::{AuthorisedEntry, Entry},
    },
    session::{channels::ChannelSenders, resource::ResourceMap, Error},
};

#[derive(Debug, Clone, Default)]
pub struct StaticTokens(Rc<RefCell<Inner>>);

#[derive(Debug, Default)]
struct Inner {
    ours: ResourceMap<StaticTokenHandle, StaticToken>,
    theirs: ResourceMap<StaticTokenHandle, StaticToken>,
}

impl StaticTokens {
    pub fn bind_theirs(&self, token: StaticToken) {
        self.0.borrow_mut().theirs.bind(token);
    }

    pub async fn bind_and_send_ours(
        &self,
        static_token: StaticToken,
        send: &ChannelSenders,
    ) -> Result<StaticTokenHandle, Error> {
        let (handle, is_new) = { self.0.borrow_mut().ours.bind_if_new(static_token.clone()) };
        if is_new {
            let msg = SetupBindStaticToken { static_token };
            send.send(msg).await?;
        }
        Ok(handle)
    }

    pub async fn authorise_entry_eventually(
        &self,
        entry: Entry,
        static_token_handle: StaticTokenHandle,
        dynamic_token: DynamicToken,
    ) -> Result<AuthorisedEntry, Error> {
        let inner = self.0.clone();
        let static_token = poll_fn(move |cx| {
            let mut inner = inner.borrow_mut();
            let token = ready!(inner.theirs.poll_get_eventually(static_token_handle, cx));
            Poll::Ready(token.clone())
        })
        .await;

        let authorised_entry =
            AuthorisedEntry::try_from_parts(entry, static_token.clone(), dynamic_token)?;

        Ok(authorised_entry)
    }
}