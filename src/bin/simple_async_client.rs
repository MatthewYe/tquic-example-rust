// Copyright (c) 2023 The TQUIC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use clap::Parser;
use log::{debug, error};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time;
use tquic::{Config, Connection, Endpoint, Error, PacketInfo, TlsConfig, TransportHandler};

use tquic_example_rust::Result;

#[derive(Parser, Debug, Clone)]
#[clap(name = "async_client")]
pub struct AsyncClientOpt {
    /// Log level, support OFF/ERROR/WARN/INFO/DEBUG/TRACE.
    #[clap(long, default_value = "INFO", value_name = "STR")]
    pub log_level: log::LevelFilter,

    /// Override server's address.
    #[clap(short, long, value_name = "ADDR")]
    pub connect_to: SocketAddr,

    /// Connection idle timeout in microseconds.
    #[clap(long, default_value = "5000", value_name = "TIME")]
    pub idle_timeout: u64,

    /// File used for session resumption.
    #[clap(long, value_name = "FILE")]
    pub session_file: Option<String>,

    /// Save TLS key log into the given file.
    #[clap(long, value_name = "FILE")]
    pub keylog_file: Option<String>,

    /// Save QUIC qlog into the given file.
    #[clap(long, value_name = "FILE")]
    pub qlog_file: Option<String>,
}

const MAX_BUF_SIZE: usize = 65536;

// 异步版本的UDP socket包装器
struct AsyncQuicSocket {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
}

impl AsyncQuicSocket {
    async fn new(is_ipv4: bool) -> Result<Self> {
        let addr = if is_ipv4 { "0.0.0.0:0" } else { "[::]:0" };

        let socket = UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;

        Ok(Self {
            socket: Arc::new(socket),
            local_addr,
        })
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

// 实现PacketSendHandler trait
impl tquic::PacketSendHandler for AsyncQuicSocket {
    fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> tquic::Result<usize> {
        let socket = self.socket.clone();

        // 在同步上下文中发送数据包
        // 注意：这不是真正的异步，但TQUIC API要求同步发送
        let mut count = 0;
        for (pkt, info) in pkts {
            // 使用try_send_to避免阻塞
            match socket.try_send_to(pkt, info.dst) {
                Ok(n) => {
                    debug!("written {} bytes", n);
                    count += 1;
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("socket send would block");
                        return Ok(count);
                    }
                    return Err(tquic::Error::InvalidOperation(format!(
                        "socket send_to(): {:?}",
                        e
                    )));
                }
            }
        }
        Ok(count)
    }
}

// 客户端上下文
struct AsyncClientContext {
    finish: bool,
}

impl AsyncClientContext {
    fn new() -> Self {
        Self { finish: false }
    }

    fn set_finish(&mut self, finish: bool) {
        self.finish = finish
    }

    fn finish(&self) -> bool {
        self.finish
    }
}

// 异步客户端处理器
struct AsyncClientHandler {
    session_file: Option<String>,
    keylog_file: Option<String>,
    qlog_file: Option<String>,
    context: Arc<Mutex<AsyncClientContext>>,
    buf: Vec<u8>,
}

impl AsyncClientHandler {
    fn new(option: &AsyncClientOpt, context: Arc<Mutex<AsyncClientContext>>) -> Self {
        Self {
            session_file: option.session_file.clone(),
            keylog_file: option.keylog_file.clone(),
            qlog_file: option.qlog_file.clone(),
            context,
            buf: vec![0; MAX_BUF_SIZE],
        }
    }
}

impl TransportHandler for AsyncClientHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        debug!("{} connection is created", conn.trace_id());

        if let Some(session_file) = &self.session_file {
            if let Ok(session) = std::fs::read(session_file) {
                if conn.set_session(&session).is_err() {
                    error!("{} session resumption failed", conn.trace_id());
                }
            }
        }

        if let Some(keylog_file) = &self.keylog_file {
            if let Ok(file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(keylog_file)
            {
                conn.set_keylog(Box::new(file));
            } else {
                error!("{} set key log failed", conn.trace_id());
            }
        }

        if let Some(qlog_file) = &self.qlog_file {
            if let Ok(qlog) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(qlog_file)
            {
                conn.set_qlog(
                    Box::new(qlog),
                    "client qlog".into(),
                    format!("id={}", conn.trace_id()),
                );
            } else {
                error!("{} set qlog failed", conn.trace_id());
            }
        }
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        debug!("{} connection is established", conn.trace_id());

        match conn.stream_write(0, Bytes::from_static(b"GET /\r\n"), true) {
            Ok(_) | Err(Error::Done) => {}
            Err(e) => {
                error!("stream send failed {:?}", e);
            }
        };
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        debug!("{} connection is closed", conn.trace_id());
        let mut context = self.context.lock().unwrap();
        context.set_finish(true);
        if let Some(session_file) = &self.session_file {
            if let Some(session) = conn.session() {
                std::fs::write(session_file, session).ok();
            }
        }
    }

    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!("{} stream {} is created", conn.trace_id(), stream_id);
    }

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        match conn.stream_read(stream_id, &mut self.buf) {
            Ok((n, fin)) => {
                debug!(
                    "{} read {} bytes from stream {}",
                    conn.trace_id(),
                    n,
                    stream_id
                );
                if let Ok(data) = String::from_utf8(self.buf[..n].to_vec()) {
                    print!("{}", data);
                }
                if fin {
                    match conn.close(true, 0x00, b"ok") {
                        Ok(_) | Err(Error::Done) => (),
                        Err(e) => panic!("error closing conn: {:?}", e),
                    }
                }
            }
            Err(Error::Done) => {}
            Err(e) => {
                error!(
                    "{} read from stream {} error {}",
                    conn.trace_id(),
                    stream_id,
                    e
                );
            }
        }
    }

    fn on_stream_writable(&mut self, _conn: &mut Connection, _stream_id: u64) {}

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!("{} stream {} is closed", conn.trace_id(), stream_id,);
    }

    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}
}

// 适配器结构体，将 Arc<AsyncQuicSocket> 转换为可以被 Rc 包装的 PacketSendHandler
struct AsyncSocketAdapter {
    socket: Arc<AsyncQuicSocket>,
}

impl AsyncSocketAdapter {
    fn new(socket: AsyncQuicSocket) -> Self {
        Self {
            socket: Arc::new(socket),
        }
    }
}

impl tquic::PacketSendHandler for AsyncSocketAdapter {
    fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> tquic::Result<usize> {
        self.socket.on_packets_send(pkts)
    }
}

// 异步客户端
struct AsyncClient {
    endpoint: Endpoint,
    socket: Arc<UdpSocket>,
    context: Arc<Mutex<AsyncClientContext>>,
    recv_buf: Vec<u8>,
}

impl AsyncClient {
    async fn new(option: &AsyncClientOpt) -> Result<Self> {
        let mut config = Config::new()?;
        config.set_max_idle_timeout(option.idle_timeout);

        let tls_config = TlsConfig::new_client_config(vec![b"http/0.9".to_vec()], false)?;
        config.set_tls_config(tls_config);

        let context = Arc::new(Mutex::new(AsyncClientContext::new()));
        let handlers = AsyncClientHandler::new(option, context.clone());

        let quic_socket = AsyncQuicSocket::new(option.connect_to.is_ipv4()).await?;
        let socket = quic_socket.socket.clone();

        // 使用适配器
        let adapter = AsyncSocketAdapter::new(quic_socket);
        let adapter_rc = Rc::new(adapter);

        Ok(AsyncClient {
            endpoint: Endpoint::new(Box::new(config), false, Box::new(handlers), adapter_rc),
            socket,
            context,
            recv_buf: vec![0u8; MAX_BUF_SIZE],
        })
    }

    fn finish(&self) -> bool {
        let context = self.context.lock().unwrap();
        context.finish()
    }

    async fn run(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) -> Result<()> {
        // 连接到服务器
        self.endpoint
            .connect(local_addr, remote_addr, None, None, None, None)?;

        // 创建接收缓冲区
        let mut buf = vec![0u8; MAX_BUF_SIZE];

        // 主事件循环
        loop {
            // 处理连接
            self.endpoint.process_connections()?;

            // 检查是否完成
            if self.finish() {
                break;
            }

            // 获取超时时间
            let timeout = self.endpoint.timeout();
            let timeout_duration = if timeout.is_some() {
                Duration::from_millis(10) // 使用较短的超时时间
            } else {
                Duration::from_millis(100) // 默认超时时间
            };

            // 使用tokio::select处理多个异步事件
            tokio::select! {
                // 接收数据包
                recv_result = self.socket.recv_from(&mut buf) => {
                    match recv_result {
                        Ok((len, remote)) => {
                            debug!("socket recv {} bytes from {:?}", len, remote);
                            let pkt_buf = &mut buf[..len];
                            let pkt_info = PacketInfo {
                                src: remote,
                                dst: self.socket.local_addr()?,
                                time: Instant::now(),
                            };

                            // 处理接收到的数据包
                            match self.endpoint.recv(pkt_buf, &pkt_info) {
                                Ok(_) => {}
                                Err(e) => {
                                    error!("recv failed: {:?}", e);
                                }
                            };
                        }
                        Err(e) => {
                            error!("socket recv error: {:?}", e);
                        }
                    }
                }

                // 处理超时
                _ = time::sleep(timeout_duration) => {
                    self.endpoint.on_timeout(Instant::now());
                }
            }
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let option = AsyncClientOpt::parse();

    // 初始化日志
    env_logger::builder().filter_level(option.log_level).init();

    // 创建异步客户端
    let mut client = AsyncClient::new(&option).await?;

    // 获取本地地址
    let local_addr = client.socket.local_addr()?;

    // 运行客户端
    client.run(local_addr, option.connect_to).await?;

    Ok(())
}
