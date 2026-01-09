use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;
use serde_json::{json, Value};

// Test that a JSON-RPC request can be sent and a response received
#[test]
fn test_client_server_create_request() {
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("test.sock");
    let socket_path_clone = socket_path.clone();

    // Spawn mock server in background thread
    let server_handle = thread::spawn(move || {
        let listener = UnixListener::bind(&socket_path_clone).unwrap();
        
        // Accept one connection
        let (mut stream, _) = listener.accept().unwrap();
        
        // Read request
        let mut reader = BufReader::new(&stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        
        let request: Value = serde_json::from_str(&request_line).unwrap();
        
        // Verify request structure
        assert_eq!(request["jsonrpc"], "2.0");
        assert_eq!(request["method"], "create");
        assert_eq!(request["params"]["containerId"], "test-container");
        
        // Send mock response
        let response = json!({
            "jsonrpc": "2.0",
            "result": {
                "status": "created",
                "id": "test-container"
            },
            "id": request["id"]
        });
        
        let response_str = serde_json::to_string(&response).unwrap() + "\n";
        stream.write_all(response_str.as_bytes()).unwrap();
    });

    // Give server time to start
    thread::sleep(Duration::from_millis(100));

    // Act as client
    let mut client = UnixStream::connect(&socket_path).unwrap();
    
    let request = json!({
        "jsonrpc": "2.0",
        "method": "create",
        "params": {
            "bundlePath": "/bundle/path",
            "containerId": "test-container"
        },
        "id": 1
    });
    
    let request_json = serde_json::to_string(&request).unwrap() + "\n";
    client.write_all(request_json.as_bytes()).unwrap();
    
    // Read response
    let mut reader = BufReader::new(&client);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).unwrap();
    
    let response: Value = serde_json::from_str(&response_line).unwrap();
    
    // Verify response
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["result"]["status"], "created");
    assert_eq!(response["result"]["id"], "test-container");
    
    server_handle.join().unwrap();
}

#[test]
fn test_client_server_start_request() {
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("test.sock");
    let socket_path_clone = socket_path.clone();

    let server_handle = thread::spawn(move || {
        let listener = UnixListener::bind(&socket_path_clone).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        
        let mut reader = BufReader::new(&stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        
        let request: Value = serde_json::from_str(&request_line).unwrap();
        
        assert_eq!(request["method"], "start");
        assert_eq!(request["params"]["containerId"], "test-container");
        
        let response = json!({
            "jsonrpc": "2.0",
            "result": {
                "status": "started",
                "id": "test-container"
            },
            "id": request["id"]
        });
        
        let response_str = serde_json::to_string(&response).unwrap() + "\n";
        stream.write_all(response_str.as_bytes()).unwrap();
    });

    thread::sleep(Duration::from_millis(100));

    let mut client = UnixStream::connect(&socket_path).unwrap();
    
    let request = json!({
        "jsonrpc": "2.0",
        "method": "start",
        "params": {
            "containerId": "test-container"
        },
        "id": 1
    });
    
    let request_json = serde_json::to_string(&request).unwrap() + "\n";
    client.write_all(request_json.as_bytes()).unwrap();
    
    let mut reader = BufReader::new(&client);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).unwrap();
    
    let response: Value = serde_json::from_str(&response_line).unwrap();
    
    assert_eq!(response["result"]["status"], "started");
    
    server_handle.join().unwrap();
}

#[test]
fn test_client_server_kill_request() {
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("test.sock");
    let socket_path_clone = socket_path.clone();

    let server_handle = thread::spawn(move || {
        let listener = UnixListener::bind(&socket_path_clone).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        
        let mut reader = BufReader::new(&stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        
        let request: Value = serde_json::from_str(&request_line).unwrap();
        
        assert_eq!(request["method"], "kill");
        
        let response = json!({
            "jsonrpc": "2.0",
            "result": {
                "status": "killed",
                "id": request["params"]["containerId"]
            },
            "id": request["id"]
        });
        
        let response_str = serde_json::to_string(&response).unwrap() + "\n";
        stream.write_all(response_str.as_bytes()).unwrap();
    });

    thread::sleep(Duration::from_millis(100));

    let mut client = UnixStream::connect(&socket_path).unwrap();
    
    let request = json!({
        "jsonrpc": "2.0",
        "method": "kill",
        "params": {
            "containerId": "test-container"
        },
        "id": 1
    });
    
    let request_json = serde_json::to_string(&request).unwrap() + "\n";
    client.write_all(request_json.as_bytes()).unwrap();
    
    let mut reader = BufReader::new(&client);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).unwrap();
    
    let response: Value = serde_json::from_str(&response_line).unwrap();
    
    assert_eq!(response["result"]["status"], "killed");
    
    server_handle.join().unwrap();
}

#[test]
fn test_client_server_delete_request() {
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("test.sock");
    let socket_path_clone = socket_path.clone();

    let server_handle = thread::spawn(move || {
        let listener = UnixListener::bind(&socket_path_clone).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        
        let mut reader = BufReader::new(&stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        
        let request: Value = serde_json::from_str(&request_line).unwrap();
        
        assert_eq!(request["method"], "delete");
        
        let response = json!({
            "jsonrpc": "2.0",
            "result": {
                "status": "deleted",
                "id": request["params"]["containerId"]
            },
            "id": request["id"]
        });
        
        let response_str = serde_json::to_string(&response).unwrap() + "\n";
        stream.write_all(response_str.as_bytes()).unwrap();
    });

    thread::sleep(Duration::from_millis(100));

    let mut client = UnixStream::connect(&socket_path).unwrap();
    
    let request = json!({
        "jsonrpc": "2.0",
        "method": "delete",
        "params": {
            "containerId": "test-container"
        },
        "id": 1
    });
    
    let request_json = serde_json::to_string(&request).unwrap() + "\n";
    client.write_all(request_json.as_bytes()).unwrap();
    
    let mut reader = BufReader::new(&client);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).unwrap();
    
    let response: Value = serde_json::from_str(&response_line).unwrap();
    
    assert_eq!(response["result"]["status"], "deleted");
    
    server_handle.join().unwrap();
}

#[test]
fn test_error_response_handling() {
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("test.sock");
    let socket_path_clone = socket_path.clone();

    let server_handle = thread::spawn(move || {
        let listener = UnixListener::bind(&socket_path_clone).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        
        let mut reader = BufReader::new(&stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        
        let request: Value = serde_json::from_str(&request_line).unwrap();
        
        // Send error response
        let response = json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": "Container not found"
            },
            "id": request["id"]
        });
        
        let response_str = serde_json::to_string(&response).unwrap() + "\n";
        stream.write_all(response_str.as_bytes()).unwrap();
    });

    thread::sleep(Duration::from_millis(100));

    let mut client = UnixStream::connect(&socket_path).unwrap();
    
    let request = json!({
        "jsonrpc": "2.0",
        "method": "start",
        "params": {
            "containerId": "nonexistent"
        },
        "id": 1
    });
    
    let request_json = serde_json::to_string(&request).unwrap() + "\n";
    client.write_all(request_json.as_bytes()).unwrap();
    
    let mut reader = BufReader::new(&client);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).unwrap();
    
    let response: Value = serde_json::from_str(&response_line).unwrap();
    
    assert!(response["error"].is_object());
    assert_eq!(response["error"]["code"], -32000);
    assert!(response["error"]["message"].as_str().unwrap().contains("not found"));
    
    server_handle.join().unwrap();
}

#[test]
fn test_invalid_json_from_server() {
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("test.sock");
    let socket_path_clone = socket_path.clone();

    let server_handle = thread::spawn(move || {
        let listener = UnixListener::bind(&socket_path_clone).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        
        let mut reader = BufReader::new(&stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        
        // Send invalid JSON
        stream.write_all(b"{ invalid json }\n").unwrap();
    });

    thread::sleep(Duration::from_millis(100));

    let mut client = UnixStream::connect(&socket_path).unwrap();
    
    let request = json!({
        "jsonrpc": "2.0",
        "method": "create",
        "params": {
            "bundlePath": "/bundle",
            "containerId": "test"
        },
        "id": 1
    });
    
    let request_json = serde_json::to_string(&request).unwrap() + "\n";
    client.write_all(request_json.as_bytes()).unwrap();
    
    let mut reader = BufReader::new(&client);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).unwrap();
    
    // Should fail to parse
    let result = serde_json::from_str::<Value>(&response_line);
    assert!(result.is_err());
    
    server_handle.join().unwrap();
}

#[test]
fn test_multiple_requests_sequentially() {
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("test.sock");
    let socket_path_clone = socket_path.clone();

    let server_handle = thread::spawn(move || {
        let listener = UnixListener::bind(&socket_path_clone).unwrap();
        
        // Handle 3 connections
        for i in 1..=3 {
            let (mut stream, _) = listener.accept().unwrap();
            
            let mut reader = BufReader::new(&stream);
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            
            let request: Value = serde_json::from_str(&request_line).unwrap();
            
            let response = json!({
                "jsonrpc": "2.0",
                "result": {
                    "status": "ok",
                    "request_number": i
                },
                "id": request["id"]
            });
            
            let response_str = serde_json::to_string(&response).unwrap() + "\n";
            stream.write_all(response_str.as_bytes()).unwrap();
        }
    });

    thread::sleep(Duration::from_millis(100));

    // Send 3 requests
    for i in 1..=3 {
        let mut client = UnixStream::connect(&socket_path).unwrap();
        
        let request = json!({
            "jsonrpc": "2.0",
            "method": "test",
            "params": {},
            "id": i
        });
        
        let request_json = serde_json::to_string(&request).unwrap() + "\n";
        client.write_all(request_json.as_bytes()).unwrap();
        
        let mut reader = BufReader::new(&client);
        let mut response_line = String::new();
        reader.read_line(&mut response_line).unwrap();
        
        let response: Value = serde_json::from_str(&response_line).unwrap();
        assert_eq!(response["result"]["request_number"], i);
    }
    
    server_handle.join().unwrap();
}