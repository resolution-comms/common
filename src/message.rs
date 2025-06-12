use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{ServerProfile, UserProfile};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ClientMessage {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ServerMessage {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "origin")]
pub enum NetworkMessage {
    Client {
        id: Uuid,
        peer_profile: UserProfile,
        message: ClientMessage,
    },
    Server {
        id: Uuid,
        responding_to: Option<Uuid>,
        peer_profile: ServerProfile,
        message: ServerMessage,
    },
}
