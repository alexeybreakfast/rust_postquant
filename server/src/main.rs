use tokio::sync::mpsc;
use std::sync::Arc;
// use tokio::sync::Mutex;
use std::sync::Mutex;

use scopeguard::defer;

use tokio_tungstenite::WebSocketStream;

use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use futures_util::{SinkExt, StreamExt, stream::{SplitSink, SplitStream}};
use std::net::SocketAddr;
use serde::{Serialize, Deserialize};

type Tx = mpsc::UnboundedSender<Message>;
type Rx = mpsc::UnboundedReceiver<Message>;
// type Tx = tokio_tungstenite::WebSocketStream<TcpStream>;
// type Write = SplitSink<WebSocketStream<TcpStream>, Message>;
type SharedClients = Arc<Mutex<Vec<client>>>;

type Read = SplitStream<WebSocketStream<TcpStream>>;

use base64::{Engine as _, engine::general_purpose};
use rand_core::OsRng;
use ml_kem::{
    MlKem768,
    kem::{Decapsulate, Encapsulate, Kem},
    EncodedSizeUser,
    KemCore,
};
type Ek = <MlKem768 as KemCore>::EncapsulationKey;

#[derive(Serialize, Deserialize, Debug)]
struct Mess {
    type_m: String,
    body: serde_json::Value,
}

#[derive(Debug, Clone)]
struct client {
    username: String,
    w: Tx,
    pub_key: Option<Vec<u8>>,
}

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([0,0,0,0], 2143));
    let listener = TcpListener::bind(&addr).await.expect("can't bind listener");
    let clients: SharedClients = Arc::new(Mutex::new(Vec::new()));
    // let clients_listener = Arc::clone(&clients);
    while let Ok((stream, addr)) = listener.accept().await {
        println!("new connect from {}", addr);

        let clients_for_task = Arc::clone(&clients);
        tokio::spawn(async move {
            let mut ws = tokio_tungstenite::accept_async(stream).await.expect("can't connect");
            // let (mut w, mut r) = ws.split();

            let (tx, rx) = mpsc::unbounded_channel::<Message>();

            let user = client {
                w: tx,
                username: "".to_string(),
                pub_key: None,
            };

            {
                let mut list = clients_for_task.lock().expect("can't reach data"); //.expect("can't reach data");
                list.push(user.clone());
            }

            let clients_for_handle = Arc::clone(&clients_for_task);
            handle_client(user, ws, rx, clients_for_handle).await;
        });
    }


    // loop {
    // {
        // let mut list = clients.lock().expect("can't reach data").unwrap();
        // println!("{:#?}", list);
    // }
    // };
}

async fn handle_client(mut user: client, mut ws: WebSocketStream<TcpStream>, mut rx: Rx, clients: SharedClients) {
    // defer! {
    //     let mut list = clients.lock().expect("can't reach data").expect("can't reach data");
    //     list.retain(|client| !client.w.same_channel(&user.w));
    // }

    let (mut ws_sender, mut ws_recevier) = ws.split();

    loop {
        tokio::select! {
            maybe_mess = ws_recevier.next() => {
                match maybe_mess {
                    Some(Ok(Message::Text(text))) => {
                        let clients_for_auth = Arc::clone(&clients);
                        parse_json(text, user.clone(), clients_for_auth).await;
                    },
                    Some(Ok(Message::Close(_))) | None => { break; },
                    _ => {},
                }
            }

            maybe_to_send = rx.recv() =>
                if let Some(msg) = maybe_to_send {
                    if let Err(e) = ws_sender.send(msg).await {
                        println!("can't send to ws: {:?}", e);
                        break;
                    }
                } else {
                    break;
                }
        }
    }

    println!("client disconnected");
    let mut list = clients.lock().expect("can't reach data");
    list.retain(|client| !client.w.same_channel(&user.w));
}


fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>());
}


async fn parse_json(text: String, user: client, clients: SharedClients) {
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("can't parse");

    match parsed.get("type_m").unwrap().as_str() {
        Some("key_auth") => { 
            if let Ok(key) = general_purpose::STANDARD.decode(parsed.get("body").unwrap().get("key").unwrap().as_str().unwrap()) {
                handle_auth(&key, user, clients).await
            }
        },
        Some("get_key") => {
            let clients_for_get = Arc::clone(&clients);
            if let name = parsed.get("body").unwrap().get("name").unwrap() {
                let key;
                {
                    println!("{}", name);
                    let mut list = clients_for_get.lock().expect("can't reach data");
                    if let Some(client) = list.iter_mut().find(|c| c.username == name.to_string() ) {
                        key = client.pub_key.clone();
                        let message = Mess {
                            type_m: "openkey".to_string(),
                            body: serde_json::json!({
                                "key": key,
                            }),
                        };
                        let message = serde_json::to_string(&message).expect("can't jsonize");
                        user.w.send(Message::Text(message)).expect("can't send");

                    } else {println!("no such user {}", name)};
                }
            }
        },
        Some("set_name") => {
            if let name = parsed.get("body").unwrap().get("name").unwrap() {
                set_name(user, clients, name.to_string()).await;
            }
        },
        _ => {},
    }
}

async fn handle_auth(key: &[u8], user: client, clients: SharedClients) {
    {
        let mut list = clients.lock().expect("can't reach data"); //.expect("can't reach data");
        if let Some(client) = list.iter_mut().find(|c| c.w.same_channel(&user.w)) {
            client.pub_key = Some(key.to_vec());
        }
    }

    let arr = key.try_into().expect("wrong key");
    let mut ek = Ek::from_bytes(arr);

    let mut rng = OsRng;
    if let Ok((shiphertext, shared_secret)) = ek.encapsulate(&mut rng) {
        println!("{:#?}",shared_secret);
        let message = Mess {
            type_m: String::from("shii"),
            body: serde_json::json!({
                "shi": general_purpose::STANDARD.encode(shiphertext.as_slice()),
            })
        };

        let string = serde_json::to_string(&message).expect("can't jsonize");
        user.w.send(Message::Text(string));
    } else {
        println!("Can't encapsulate");
    };
}

async fn set_name(user: client, clients: SharedClients, name: String) {
    {
        let mut list = clients.lock().expect("can't reach data"); //.expect("can't reach data");
        if let Some(client) = list.iter_mut().find(|c| c.w.same_channel(&user.w)) {
            client.username = name;
        }

    }
}
