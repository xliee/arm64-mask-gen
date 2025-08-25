# arm64-mask-gen

A Rust library for generating pattern:mask pairs from AArch64 assembly templates with wildcard support.

## Features

- Parse AArch64 assembly templates with wildcards
- Generate pattern:mask pairs for binary search
- Support for register wildcards (`X?`, `W?`)
- Support for immediate value wildcards (`#?`, `#bm?`)
- Compatible with reverse engineering tools like radare2

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
arm64-mask-gen = { version = "0.1.0", features = ["keystone"] }
```

### Simple Example with Keystone (Recommended)

```rust
use arm64_mask_gen::make_r2_mask_with_keystone;

// Generate pattern:mask directly from template
let (pattern, mask) = make_r2_mask_with_keystone("mov X?, #?")?;
println!("Pattern: {}", pattern);
println!("Mask: {}", mask);
```

### Advanced Example with Custom Assembler

```rust
use arm64_mask_gen::{parse_template, make_r2_mask_for_a64_template};
use keystone_engine::{Keystone, Arch, Mode};

// Create assembler function using Keystone
fn create_assembler() -> impl Fn(&str) -> anyhow::Result<Vec<u8>> {
    let engine = Keystone::new(Arch::ARM64, Mode::LITTLE_ENDIAN)
        .expect("Failed to create Keystone engine");
    
    move |asm: &str| {
        engine.asm(asm.to_string(), 0)
            .map(|result| result.bytes)
            .map_err(|e| anyhow::anyhow!("Assembly failed: {}", e))
    }
}

// Parse a template with wildcards
let template = "mov X?, #?";
let parsed = parse_template(template);

// Create assembler and generate pattern:mask for radare2
let assembler = create_assembler();
let (pattern, mask) = make_r2_mask_for_a64_template(&parsed, assembler)?;
println!("Pattern: {}", pattern);
println!("Mask: {}", mask);
```


### Supported Wildcards

- `X?` - Any 64-bit register (X0-X30)
- `W?` - Any 32-bit register (W0-W30)
- `#?` - Any immediate value
- `#bm?` - Bitmap immediate values

### Template Examples

```rust
// Move immediate to register
"mov X?, #?"

// Add with immediate
"add X?, X?, #?"

// Load/store operations
"ldr X?, [X?, #?]"
"str W?, [X?, #?]"

// Conditional operations
"cmp X?, #?"
"b.eq #?"
```

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Integrations

- [`arm64-mask-gen-py`](https://github.com/xliee/arm64-mask-gen-py) — a PyO3 wrapper that exposes a Python module `arm64_mask_gen_py`. Build with `maturin` and enable the `keystone` feature if you want assembler support.
- [`ida_mask_plugin`](https://github.com/xliee/ida_mask_plugin) — an IDA Pro plugin (Python) which uses the Python wrapper to generate `pattern:mask` pairs from assembly snippets and perform masked searches inside an IDB.

