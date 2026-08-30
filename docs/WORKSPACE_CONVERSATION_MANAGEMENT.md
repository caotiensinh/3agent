# WorkSpace Conversation Management

## Scope

WorkSpace conversation management adds user-facing rename, archive, restore and delete operations to the local account-scoped chat history. These operations do not grant any new network, model, filesystem or egress authority.

## Ownership invariant

Every lifecycle mutation is authorized by the authenticated local account on the server. The browser cannot select a different owner by changing JavaScript, request JSON or a conversation ID.

The backend derives the owner key from the authenticated WorkSpace account and applies it to every query and mutation:

```text
authenticated account
        |
        v
workspace-user:<user_id>
        |
        v
server-derived history owner key
        |
        +--> list/get
        +--> rename
        +--> pin/unpin
        +--> archive/restore
        +--> delete
```

A foreign conversation ID returns not-found rather than exposing whether that conversation exists for another account.

## Schema migration

The existing `chat_conversations` table is upgraded additively with:

```text
archived INTEGER NOT NULL DEFAULT 0
```

The migration is idempotent. Existing conversations therefore remain active after upgrade and their messages are not rewritten.

## Rename

- Titles are normalized to single-space separators.
- Empty titles are rejected.
- Stored titles remain capped at 96 characters.
- Rename does not change conversation ownership or message content.

## Archive and restore

Archiving a conversation:

- removes it from the default active history view;
- clears its pinned state;
- preserves all saved messages;
- keeps it visible in the Archived view and global search;
- prevents new messages from being appended until it is restored.

Restoring returns the conversation to the active history view.

## Delete

Delete is permanent for the local WorkSpace history record. The `chat_messages` rows are removed through the existing SQLite foreign-key cascade.

The frontend requires a confirmation step, but server-side ownership validation remains the security boundary. A crafted request cannot delete another account's conversation.

## Sidebar behavior

The sidebar now provides:

- per-conversation `...` menu;
- Rename;
- Pin / Unpin;
- Archive / Restore;
- Delete with confirmation;
- Archived chats view;
- active chat grouping by `Today`, `Yesterday`, `Previous 7 days` and `Older`;
- global search across active and archived conversations.

Pinned active chats remain in the dedicated Pinned section. Archived chats cannot be pinned.

## API surface

Authenticated owner-scoped endpoints:

```text
GET  /api/conversations?view=active|archived|all&q=<query>
GET  /api/conversations/<conversation_id>
POST /api/conversations/<conversation_id>/pin
POST /api/conversations/<conversation_id>/rename
POST /api/conversations/<conversation_id>/archive
POST /api/conversations/<conversation_id>/delete
```

`view=all` is used for global history search. It does not bypass account ownership.
