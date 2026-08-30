# WorkSpace Projects

WorkSpace projects are local, account-scoped folders for organizing saved conversations.
They do not grant new model, Internet, filesystem, GitHub, or administrator capabilities.

## Security boundary

- Every project row is bound to the same server-derived `owner_key` used by chat history.
- Project IDs supplied by the browser are never treated as authorization.
- Create/list/rename/delete operations require an authenticated local account.
- Moving a conversation requires both the conversation and destination project to belong to the current account.
- Cross-account project or conversation references fail closed as not-found.
- The browser cannot assign another user's conversation to its own project by editing request JSON.

## Persistence model

`workspace_projects` stores only project metadata:

- project ID;
- owner key;
- display name;
- created/updated timestamps.

`chat_conversations.project_id` is an additive migration. Existing conversations receive an empty project ID and remain visible in the normal chat list.

Project deletion is intentionally non-destructive to chat history: conversations are detached back to the unfiled list before the project row is deleted. Conversation deletion remains a separate explicit action.

## UI behavior

The expanded sidebar contains a Projects section with:

- New project;
- project list and active conversation counts;
- project rename;
- project delete with explicit confirmation;
- project selection to filter conversation history.

Each conversation action menu includes **Move to project**. The move dialog can assign the chat to one owned project or return it to **No project**.

Global chat search remains global across projects. Archive state remains independent from project membership, so archived chats can still retain their project association and can be viewed with the project filter.

## API

- `GET /api/projects`
- `POST /api/projects`
- `POST /api/projects/<project_id>/rename`
- `POST /api/projects/<project_id>/delete`
- `POST /api/conversations/<conversation_id>/project`
- `GET /api/conversations?...&project=<project_id>`

Passing `project=` explicitly filters to unfiled chats. Omitting the project query parameter leaves the conversation list unfiltered by project.

## Non-goals for this release

This release does not copy files into projects, create project-level model memory, or grant project-specific tools. Those capabilities require separate storage, retention, retrieval, and authorization contracts before they can be enabled safely.
