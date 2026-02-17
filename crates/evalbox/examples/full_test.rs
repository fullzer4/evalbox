use evalbox::{go, python, shell};
use std::time::Duration;

fn main() {
    println!("=== Testing evalbox ===\n");

    // Shell test
    println!("1. Shell test:");
    match shell::run("echo 'Hello from shell!' && pwd").exec() {
        Ok(output) => {
            println!(
                "   Exit: {} | Success: {}",
                output.exit_code,
                output.success()
            );
            println!(
                "   Output: {}",
                output.stdout_str().lines().next().unwrap_or("")
            );
        }
        Err(e) => eprintln!("   Error: {}", e),
    }

    // Python test
    println!("\n2. Python test:");
    match python::run("print('Hello from Python!')").exec() {
        Ok(output) => {
            println!(
                "   Exit: {} | Success: {}",
                output.exit_code,
                output.success()
            );
            println!("   Output: {}", output.stdout_str().trim());
        }
        Err(e) => eprintln!("   Error: {}", e),
    }

    // Go test
    println!("\n3. Go test:");
    match go::run(r#"fmt.Println("Hello from Go!")"#)
        .timeout(Duration::from_secs(60))
        .exec()
    {
        Ok(output) => {
            println!(
                "   Exit: {} | Success: {}",
                output.exit_code,
                output.success()
            );
            println!("   Output: {}", output.stdout_str().trim());
        }
        Err(e) => eprintln!("   Error: {}", e),
    }

    println!("\n=== All tests completed ===");
}
