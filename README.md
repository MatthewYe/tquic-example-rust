# tquic-example-rust

Rust examples of using [TQUIC](https://github.com/Tencent/tquic) on Linux.

## Requirements

Refer to the [TQUIC](https://tquic.net/docs/getting_started/installation#prerequisites) prerequisites.

## Build

```shell
cargo build
```

## Run simple_server

Generate certificate and key.

```shell
cd target/debug
openssl genrsa -out cert.key 2048
openssl req -new -x509 -days 36500 -key cert.key -out cert.crt -subj "/CN=example.org"
```

Run simple_server.

```shell
./simple_server
```

## Run simple_client

```shell
cd target/debug
./simple_client -c 127.0.0.1:4433
```

## Run simple_async_server

Generate certificate and key (if not already done).

```shell
cd target/debug
openssl genrsa -out cert.key 2048
openssl req -new -x509 -days 36500 -key cert.key -out cert.crt -subj "/CN=example.org"
```

Run simple_async_server.

```shell
./simple_async_server
```

You can customize the server with command line options:

```shell
./simple_async_server -l 127.0.0.1:4433 --log-level DEBUG
```

## Run simple_async_client

```shell
cd target/debug
./simple_async_client -c 127.0.0.1:4433
```

You can customize the client with command line options:

```shell
./simple_async_client -c 127.0.0.1:4433 --log-level DEBUG --idle-timeout 10000 --qlog-file client.qlog
```

Available options include:
- `-c, --connect-to`: Server address to connect to
- `--log-level`: Log level (OFF/ERROR/WARN/INFO/DEBUG/TRACE)
- `--idle-timeout`: Connection idle timeout in microseconds
- `--session-file`: File used for session resumption
- `--keylog-file`: Save TLS key log into the given file
- `--qlog-file`: Save QUIC qlog into the given file

The async server and client implementations use Tokio for asynchronous I/O operations, providing better scalability for handling multiple connections.