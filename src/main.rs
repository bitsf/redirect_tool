use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use clap::{Command, Arg};
use anyhow::{Result, Context};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::{timeout, Duration};
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

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
    let blacklist = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (socket, addr) = listener.accept().await?;
        let forward_addr = forward_addr.to_string();
        let password = password.to_string();
        let user_map: Arc<Mutex<HashMap<String, ()>>> = Arc::clone(&user_map);
        let blacklist: Arc<Mutex<HashMap<String, (u32, u64, u64)>>> = Arc::clone(&blacklist);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, addr.ip().to_string(), forward_addr, password, user_map, blacklist).await {
                eprintln!("Failed to handle connection: {}", e);
            }
        });
    }
}

async fn handle_connection(mut socket: TcpStream, addr: String, forward_addr: String, password: String, user_map: Arc<Mutex<HashMap<String, ()>>>, blacklist: Arc<Mutex<HashMap<String, (u32, u64, u64)>>>) -> Result<()> {
    {
        let should_ban = {
            let blacklist = blacklist.lock().unwrap();
            let result = if let Some((count, _, _)) = blacklist.get(&addr) {
                *count >= 3
            } else {
                false
            };
            result
        };

        if should_ban {
            println!("{} is banned", addr);
            return Ok(());
        }
    }

    let is_authenticated = {
        let users = user_map.lock().unwrap();
        users.contains_key(&addr)
    };

    if is_authenticated {
        println!("{} already authenticated", addr);
        // IP already authenticated, allow forwarding
        let mut forward_socket = TcpStream::connect(forward_addr).await
            .context("Failed to connect to forward address")?;

        tokio::spawn(async move {
            let _ = timeout(Duration::from_secs(300), async {
                tokio::io::copy_bidirectional(&mut socket, &mut forward_socket).await
            }).await;
        });

        return Ok(());
    }

    println!("{} not authenticated", addr);
    socket.write_all(b"please input password: ").await?;

    let mut buf = [0; 1024];
    let n = socket.read(&mut buf).await?;
    let input_password = String::from_utf8_lossy(&buf[..n]).trim().to_string();

    if input_password != password {
        let mut blacklist = blacklist.lock().unwrap();
        let entry = blacklist.entry(addr.clone()).or_insert((0, SystemTime::now().elapsed().unwrap().as_secs(), SystemTime::now().elapsed().unwrap().as_secs()));
        entry.0 += 1;

        println!("{} failed to authenticate {} times", addr, entry.0);
        return Ok(());
    }

    {
        let mut users = user_map.lock().unwrap();
        users.insert(addr.clone(), ());
    }

    println!("{} authenticated", addr);
    socket.write_all(b"validated\n").await?;
    return Ok(());
}

fn generate_random_password() -> String {
    use rand::Rng;
    let chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    let mut rng = rand::thread_rng();
    (0..8).map(|_| chars[rng.gen_range(0..chars.len())]).collect()
}