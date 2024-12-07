use anyhow::{Context, Result};
use clap::{Arg, Command};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Duration;

const SCAN_TIME: u64 = 60;
const CLEAN_TIME: u64 = 3600;
const BAN_TIME: u64 = 3600;

struct UserInfo {
    count: u32,
    create_time: u64,
    update_time: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let now = SystemTime::now();
    let matches = Command::new("redirect_tool")
        .version("1.0")
        .author("Author Name <email@example.com>")
        .about("A command line tool for network redirection")
        .arg(
            Arg::new("listen")
                .help("The local address to listen on")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("forward")
                .help("The target address to forward to")
                .required(true)
                .index(2),
        )
        .arg(
            Arg::new("password")
                .short('p')
                .long("password")
                .help("The preset password")
                .num_args(1),
        )
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

    let listener = TcpListener::bind(listen_addr)
        .await
        .context("Failed to bind to address")?;
    let user_map: Arc<Mutex<HashMap<String, UserInfo>>> = Arc::new(Mutex::new(HashMap::new()));
    let user_map_cleanup = Arc::clone(&user_map);
    let blacklist = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(SCAN_TIME)).await;
            let current_time = now.elapsed().unwrap().as_secs();
            // clean up user_map
            let mut users = user_map_cleanup.lock().unwrap();
            let old_user_count = users.len();
            users.retain(|_, user_info| {
                user_info.count > 0 || current_time - user_info.update_time <= CLEAN_TIME
            });
            if old_user_count!= users.len(){
                println!("remaining users: {} -> {}", old_user_count, users.len());
            }

            // clean up blacklist
            let mut blacklist = blacklist.lock().unwrap();
            let old_blacklist_count = blacklist.len();
            blacklist.retain(|_, (_, _, update_time)| {
                current_time - *update_time <= BAN_TIME
            });
            if old_blacklist_count != blacklist.len(){
                println!("remaining blacklist: {} -> {}", old_blacklist_count, blacklist.len());
            }
        }
    });

    

    loop {
        let (socket, addr) = listener.accept().await?;
        let forward_addr = forward_addr.to_string();
        let password = password.to_string();
        let user_map: Arc<Mutex<HashMap<String, UserInfo>>> = Arc::clone(&user_map);
        let blacklist: Arc<Mutex<HashMap<String, (u32, u64, u64)>>> = Arc::clone(&blacklist);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                now,
                socket,
                addr.ip().to_string(),
                forward_addr,
                password,
                user_map,
                blacklist,
            )
            .await
            {
                eprintln!("Failed to handle connection: {}", e);
            }
        });
    }
}

struct OneConn {
    now: SystemTime,
    addr: String,
    user_map: Arc<Mutex<HashMap<String, UserInfo>>>,
}

impl Drop for OneConn {
    fn drop(&mut self) {
        let mut users = self.user_map.lock().unwrap();
        if let Some(user_info) = users.get_mut(&self.addr) {
            let current_time = self.now.elapsed().unwrap().as_secs();
            println!(
                "{} close conn {} at {} -> {} -> {}",
                self.addr, user_info.count, user_info.create_time, user_info.update_time, current_time
            );
            user_info.count -= 1;
            user_info.update_time = current_time;
        };
    }
}

async fn handle_connection(
    now: SystemTime,
    mut socket: TcpStream,
    addr: String,
    forward_addr: String,
    password: String,
    user_map: Arc<Mutex<HashMap<String, UserInfo>>>,
    blacklist: Arc<Mutex<HashMap<String, (u32, u64, u64)>>>,
) -> Result<()> {
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
        let mut users = user_map.lock().unwrap();
        let result = if let Some(user_info) = users.get_mut(&addr) {
            let current_time = now.elapsed().unwrap().as_secs();
            println!(
                "{} already authenticated {} at {} -> {} -> {}",
                addr, user_info.count, user_info.create_time, user_info.update_time, current_time
            );
            user_info.update_time = current_time;
            user_info.count += 1;
            true
        } else {
            false
        };
        result
    };

    if is_authenticated {
        // IP already authenticated, allow forwarding
        let mut forward_socket = TcpStream::connect(forward_addr)
            .await
            .context("Failed to connect to forward address")?;

        let one_conn = OneConn {
            now: now,
            addr: addr.clone(),
            user_map: user_map,
        };

        tokio::spawn(async move {
            let _one_conn = one_conn;
            tokio::io::copy_bidirectional(&mut socket, &mut forward_socket).await.unwrap();
            println!("{} disconnected", addr);
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
        let entry = blacklist.entry(addr.clone()).or_insert((
            0,
            now.elapsed().unwrap().as_secs(),
            now.elapsed().unwrap().as_secs(),
        ));
        entry.0 += 1;
        entry.2 = now.elapsed().unwrap().as_secs();

        println!("{} failed to authenticate {} times", addr, entry.0);
        return Ok(());
    }

    {
        let mut users = user_map.lock().unwrap();
        users.entry(addr.clone()).or_insert(UserInfo {
            count: 0,
            create_time: now.elapsed().unwrap().as_secs(),
            update_time: now.elapsed().unwrap().as_secs(),
        });
    }

    println!("{} authenticated", addr);
    socket.write_all(b"validated\n").await?;
    return Ok(());
}

fn generate_random_password() -> String {
    use rand::Rng;
    let chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        .chars()
        .collect();
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect()
}
