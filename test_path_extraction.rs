fn extract_path(request: &str) -> Option<String> {
    // Parse the first line of the HTTP request: "METHOD /path HTTP/version"
    let first_line = request.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() >= 2 {
        Some(parts[1].to_string())
    } else {
        None
    }
}

fn main() {
    // Test cases
    let test1 = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let test2 = "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let test3 = "POST /users/create HTTP/1.1\r\nHost: localhost\r\n\r\n";
    
    println!("Test 1: {:?}", extract_path(test1));  // Should print: Some("/")
    println!("Test 2: {:?}", extract_path(test2));  // Should print: Some("/api/status")
    println!("Test 3: {:?}", extract_path(test3));  // Should print: Some("/users/create")
}
