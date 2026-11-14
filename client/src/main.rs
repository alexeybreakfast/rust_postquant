use futures_util::stream::{SplitSink, SplitStream};
use tokio::net::TcpStream;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::{connect_async, tungstenite::Message};

use serde::{Serialize, Deserialize};
use serde_json;
use futures_util::{SinkExt, StreamExt};

use std::io;
use tokio::time::{sleep, Duration};
// use tokio::net::TcpStream;


use ml_kem::kem::Decapsulate;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;

use base64::{Engine as _, engine::general_purpose};

#[derive(Serialize, Deserialize, Debug)]
struct Mess {
    type_m: String,
    body: serde_json::Value,
}

type Read = SplitStream<WebSocketStream<TcpStream>>;
type Write = SplitSink<WebSocketStream<TcpStream>, Message>;

type Dk = <MlKem768 as KemCore>::DecapsulationKey;

#[tokio::main]
async fn main() {
    if let Ok((mut ws, _)) = connect_async("ws://127.0.0.1:2143").await {
        let (private_key, public_key) = MlKem768::generate(&mut OsRng);

        // SENDING OPEN KEY TO SERVER
        let message = Mess {
            type_m: String::from("key_auth"),
            body: serde_json::json!({
                "key": general_purpose::STANDARD.encode(public_key.as_bytes())
            }),
        };
        let string = serde_json::to_string(&message).expect("can't do");
        ws.send(Message::Text(string)).await.expect("oups");

        let shiphertext;
        if let Some(Ok(Message::Text(text))) = ws.next().await {
            let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
            if parsed.get("type_m").unwrap() == "shii" {
                if let Ok(sometext) = general_purpose::STANDARD.decode(parsed.get("body").unwrap().get("shi").unwrap().as_str().unwrap()) {
                    shiphertext = sometext;

                    let message = Mess {
                        type_m: "name".to_string(),
                        body: serde_json::json!({
                            "name": "avahi"
                        })
                    };
                    ws.send(Message::Text(serde_json::to_string(&message).unwrap())).await.unwrap();

                    client(ws, shiphertext, private_key).await;
                }
            }
        }



        // tokio::spawn(
        //     async move {
        //         while let Some(res) = ws_get.next().await {
        //             match res {
        //                 Ok(Message::Text(text)) => {
        //                     parse_json(&text);
        //                 },
        //                 _ => {},
        //             }
        //         }
        //     }
        //     );
    }
}

async fn client<S>(mut ws: WebSocketStream<S>, shiphertext: Vec<u8>, private_key: Dk)
where S: AsyncRead + AsyncWrite + Unpin,
{
    let arr = shiphertext.as_slice().try_into().expect("wrong shiphrotext");
    let secret = private_key.decapsulate(arr).expect("can't decapsulate");
    println!("{:#?}, {}", secret, secret.len());

    println!("insert name");
    let mut name = "".to_string();
    io::stdin().read_line(&mut name).expect("can't read stdin");
    let name = name.trim().to_string();
    get_name(name, ws).await;
}

async fn get_name<S>(name: String, mut ws: WebSocketStream<S>)
where S: AsyncRead + AsyncWrite + Unpin,
{
    let message = Mess {
        type_m: "get_key".to_string(),
        body: serde_json::json!({
            "name": name,
        }),
    };
    let message = serde_json::to_string(&message).expect("can't jsonize");
    ws.send(Message::Text(message)).await.expect("can't send");
}

fn parse_json(test: &String) {}
