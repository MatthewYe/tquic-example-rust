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

use std::fs::File;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use clap::Parser;
use log::{debug, error};
use tokio::net::UdpSocket;
use tokio::time;
use tquic::{Config, Connection, Endpoint, Error, PacketInfo, TlsConfig, TransportHandler};

use tquic_example_rust::Result;

#[derive(Parser, Debug)]
#[clap(name = "async_server")]
pub struct AsyncServerOpt {
    /// TLS certificate in PEM format.
    #[clap(
        short,
        long = "cert",
        default_value = "./cert.crt",
        value_name = "FILE"
    )]
    pub cert_file: String,

    /// TLS private key in PEM format.
    #[clap(short, long = "key", default_value = "./cert.key", value_name = "FILE")]
    pub key_file: String,

    /// Log level, support OFF/ERROR/WARN/INFO/DEBUG/TRACE.
    #[clap(long, default_value = "INFO")]
    pub log_level: log::LevelFilter,

    /// Address to listen.
    #[clap(short, long, default_value = "0.0.0.0:4433", value_name = "ADDR")]
    pub listen: SocketAddr,

    /// Connection idle timeout in microseconds.
    #[clap(long, default_value = "5000", value_name = "TIME")]
    pub idle_timeout: u64,

    /// Save TLS key log into the given file.
    #[clap(long, value_name = "FILE")]
    pub keylog_file: Option<String>,

    /// Save QUIC qlog into the given file.
    #[clap(long, value_name = "FILE")]
    pub qlog_file: Option<String>,
}

const MAX_BUF_SIZE: usize = 65536;

/// 异步版本的UDP socket包装器
struct AsyncQuicSocket {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
}

impl AsyncQuicSocket {
    async fn new(local: &SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(local).await?;
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

/// 异步socket适配器，用于适配TQUIC的PacketSendHandler
struct AsyncSocketAdapter {
    socket: AsyncQuicSocket,
}

impl AsyncSocketAdapter {
    fn new(socket: AsyncQuicSocket) -> Self {
        Self { socket }
    }
}

impl tquic::PacketSendHandler for AsyncSocketAdapter {
    fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> tquic::Result<usize> {
        self.socket.on_packets_send(pkts)
    }
}

/// 异步服务器处理器
struct AsyncServerHandler {
    /// 读取缓冲区
    buf: Vec<u8>,

    /// SSL key logger
    keylog: Option<File>,

    /// Qlog file
    qlog: Option<File>,
}

impl AsyncServerHandler {
    fn new(option: &AsyncServerOpt) -> Result<Self> {
        let keylog = match &option.keylog_file {
            Some(keylog_file) => Some(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(keylog_file)?,
            ),
            None => None,
        };

        let qlog = match &option.qlog_file {
            Some(qlog_file) => Some(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(qlog_file)?,
            ),
            None => None,
        };

        Ok(Self {
            buf: vec![0; MAX_BUF_SIZE],
            keylog,
            qlog,
        })
    }
}

impl TransportHandler for AsyncServerHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        debug!("{} connection is created", conn.trace_id());

        if let Some(keylog) = &mut self.keylog {
            if let Ok(keylog) = keylog.try_clone() {
                conn.set_keylog(Box::new(keylog));
            }
        }

        if let Some(qlog) = &mut self.qlog {
            if let Ok(qlog) = qlog.try_clone() {
                conn.set_qlog(
                    Box::new(qlog),
                    "server qlog".into(),
                    format!("id={}", conn.trace_id()),
                );
            }
        }
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        debug!("{} connection is established", conn.trace_id());
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        debug!("connection[{:?}] is closed", conn.trace_id());
    }

    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!("{} stream {} is created", conn.trace_id(), stream_id,);
    }

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!("{} stream {} is readable", conn.trace_id(), stream_id,);

        while let Ok((read, fin)) = conn.stream_read(stream_id, &mut self.buf) {
            debug!(
                "{} read {} bytes from stream {}, fin: {}",
                conn.trace_id(),
                read,
                stream_id,
                fin
            );
            if fin {
                match conn.stream_write(stream_id, Bytes::from_static(b"HTTP/0.9 200 OK\n"), true) {
                    Ok(_) | Err(Error::Done) => {}
                    Err(e) => {
                        error!("stream send failed {:?}", e);
                    }
                };
                return;
            }
        }
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!("{} stream {} is writable", conn.trace_id(), stream_id,);
    }

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        debug!("{} stream {} is closed", conn.trace_id(), stream_id,);
    }

    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}
}

/// 异步服务器
struct AsyncServer {
    endpoint: Endpoint,
    socket: Arc<UdpSocket>,
    recv_buf: Vec<u8>,
}

impl AsyncServer {
    async fn new(option: &AsyncServerOpt) -> Result<Self> {
        // 创建配置
        let mut config = Config::new()?;
        config.set_max_idle_timeout(option.idle_timeout);

        // 设置TLS配置
        let application_protos = vec![b"http/0.9".to_vec()];
        let tls_config = TlsConfig::new_server_config(
            &option.cert_file,
            &option.key_file,
            application_protos,
            true,
        )?;
        config.set_tls_config(tls_config);

        // 创建处理器
        let handlers = AsyncServerHandler::new(option)?;

        // 创建socket
        let quic_socket = AsyncQuicSocket::new(&option.listen).await?;
        let socket = quic_socket.socket.clone();

        // 创建适配器
        let adapter = AsyncSocketAdapter::new(quic_socket);
        let adapter_rc = Rc::new(adapter);

        Ok(AsyncServer {
            endpoint: Endpoint::new(Box::new(config), true, Box::new(handlers), adapter_rc),
            socket,
            recv_buf: vec![0u8; MAX_BUF_SIZE],
        })
    }

    async fn run(&mut self) -> Result<()> {
        // 主事件循环
        loop {
            // 处理连接
            if let Err(e) = self.endpoint.process_connections() {
                error!("process connections error: {:?}", e);
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
                recv_result = self.socket.recv_from(&mut self.recv_buf) => {
                    match recv_result {
                        Ok((len, remote)) => {
                            debug!("socket recv {} bytes from {:?}", len, remote);
                            let pkt_buf = &mut self.recv_buf[..len];
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
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let option = AsyncServerOpt::parse();

    // 初始化日志
    env_logger::builder().filter_level(option.log_level).init();

    // 创建异步服务器
    let mut server = AsyncServer::new(&option).await?;

    // 运行服务器
    server.run().await?;

    Ok(())
}
