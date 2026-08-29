//! Goal: translate HTTP requests into service responses without containing
//! governance-domain behavior.

use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use crate::wiring::Application;

const DEFAULT_ADDRESS: &str = "0.0.0.0";
const DEFAULT_PORT: &str = "8080";

#[derive(Debug, Eq, PartialEq)]
pub struct Response {
    pub status: &'static str,
    pub content_type: &'static str,
    pub body: &'static str,
}

pub fn serve(application: Application) -> std::io::Result<()> {
    let address = env::var("BIND_ADDRESS").unwrap_or_else(|_| DEFAULT_ADDRESS.to_owned());
    let port = env::var("PORT").unwrap_or_else(|_| DEFAULT_PORT.to_owned());
    let listener = TcpListener::bind(format!("{address}:{port}"))?;

    println!("infernal-law listening on {address}:{port}");

    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let application = application.clone();
                thread::spawn(move || {
                    if let Err(error) = handle_connection(stream, &application) {
                        eprintln!("request failed: {error}");
                    }
                });
            }
            Err(error) => eprintln!("connection failed: {error}"),
        }
    }

    Ok(())
}

fn handle_connection(mut stream: TcpStream, application: &Application) -> std::io::Result<()> {
    let mut request = [0_u8; 1024];
    let bytes_read = stream.read(&mut request)?;
    let request_line = String::from_utf8_lossy(&request[..bytes_read]);
    let path = request_line
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let response = if path == "/health/ready" {
        readiness_response(application.database().check_connection().is_ok())
    } else {
        route(path)
    };
    let serialized = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response.status,
        response.content_type,
        response.body.len(),
        response.body
    );

    stream.write_all(serialized.as_bytes())
}

pub fn route(path: &str) -> Response {
    match path {
        "/" => Response {
            status: "200 OK",
            content_type: "application/json",
            body: "{\"service\":\"infernal-law\"}\n",
        },
        "/health/live" => Response {
            status: "200 OK",
            content_type: "text/plain",
            body: "ok\n",
        },
        _ => Response {
            status: "404 Not Found",
            content_type: "text/plain",
            body: "not found\n",
        },
    }
}

pub fn readiness_response(database_ready: bool) -> Response {
    if database_ready {
        Response {
            status: "200 OK",
            content_type: "text/plain",
            body: "ok\n",
        }
    } else {
        Response {
            status: "503 Service Unavailable",
            content_type: "text/plain",
            body: "database unavailable\n",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{readiness_response, route};

    #[test]
    fn health_endpoints_are_available() {
        assert_eq!(route("/health/live").status, "200 OK");
        assert_eq!(readiness_response(true).status, "200 OK");
    }

    #[test]
    fn readiness_fails_when_the_database_is_unavailable() {
        assert_eq!(readiness_response(false).status, "503 Service Unavailable");
    }

    #[test]
    fn unknown_routes_are_not_found() {
        assert_eq!(route("/missing").status, "404 Not Found");
    }
}
