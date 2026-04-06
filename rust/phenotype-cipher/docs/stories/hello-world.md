# Hello World Story

<StoryHeader
    title="Your First phenotype-cipher Operation"
    :duration="2"
    :gif="'/gifs/phenotype-cipher-hello-world.gif'"
    difficulty="beginner"
/>

## Objective

Get phenotype-cipher running with a basic operation.

## Prerequisites

- Rust/Node/Python installed
- phenotype-cipher package installed

## Implementation

```rust
use phenotype-cipher::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize client
    let client = Client::new().await?;
    
    // Execute operation
    let result = client.hello().await?;
    
    println!("Success: {}", result);
    Ok(())
}
```

## Expected Output

```
Success: Hello from phenotype-cipher!
```

## Next Steps

- [Core Integration](./core-integration)
- Read [API Reference](../reference/api)
