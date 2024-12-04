
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use clap::{Command, Arg};
use anyhow::{Result, Context};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::{timeout, Duration};

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Command::new("redirect_tool")
        .version("1.0")
        .author("Author Name <email@example.com>")
        .about("A command line tool for network redirection")
        .arg(Arg::new("listen")
            .help("The local address to listen on")
            .required(true)
            .index(1))
        .arg(Arg::new("forward")
            .help("The target address to forward to")
            .required(true)
            .index(2))
        .arg(Arg::new("password")
            .short('p')
            .long("password")
            .help("The preset password")
            .num_args(1))
        .get_matches();

    let listen_addr = matches.get_one::<String>("listen").unwrap();
    let forward_addr = matches.get_one::<String>("forward").unwrap();
    let password = if let Some(p) = matches.get_one::<String>("password") {
        p.to_string()
    } else {
        let random_password = generate_random_password();
        println!("Generated password: {}", random_password);
        random_password
    };

    let listener = TcpListener::bind(listen_addr).await
        .context("Failed to bind to address")?;
    let user_map = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (socket, addr) = listener.accept().await?;
        let forward_addr = forward_addr.to_string();
        let password = password.to_string();
        let user_map = Arc::clone(&user_map);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, addr.to_string(), forward_addr, password, user_map).await {
                eprintln!("Failed to handle connection: {}", e);
            }
        });
    }
}

async fn handle_connection(mut socket: TcpStream, addr: String, forward_addr: String, password: String, user_map: Arc<Mutex<HashMap<String, ()>>>) -> Result<()> {
    let mut buf = [0; 1024];
    let n = socket.read(&mut buf).await?;
    let input_password = String::from_utf8_lossy(&buf[..n]).trim().to_string();

    if input_password != password {
        socket.write_all(b"Invalid password\n").await?;
        return Ok(());
    }

    {
        let mut users = user_map.lock().unwrap();
        users.insert(addr.clone(), ());
    }

    let mut forward_socket = TcpStream::connect(forward_addr).await
        .context("Failed to connect to forward address")?;

    tokio::spawn(async move {
        let _ = timeout(Duration::from_secs(300), async {
            tokio::io::copy_bidirectional(&mut socket, &mut forward_socket).await
        }).await;
        
        let mut users = user_map.lock().unwrap();
        users.remove(&addr);
    });

    Ok(())
}

fn generate_random_password() -> String {
    use rand::Rng;
    let chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    let mut rng = rand::thread_rng();
    (0..8).map(|_| chars[rng.gen_range(0..chars.len())]).collect()
}