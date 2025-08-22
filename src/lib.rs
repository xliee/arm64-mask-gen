// Copyright (c) 2025 Logicode. Licensed under the MIT License.
// See LICENSE for details.

use anyhow::{Result, ensure};
use regex::Regex;

#[cfg(feature = "keystone")]
use keystone_engine::{Keystone, Arch, Mode};

#[derive(Debug, Clone)]
pub enum RegSpec {
    AnyGpr(bool /*is64*/),
    Range { is64: bool, lo: u8, hi: u8 },
    Set { is64: bool, vals: Vec<u8> },
    Fixed { is64: bool, num: u8 },
}

#[derive(Debug, Clone)]
pub enum ImmSpec {
    Any,
    Range { lo: u64, hi: u64, step: u64 },
    Fixed(u64),
    BitmaskAny,
}

#[derive(Debug, Clone)]
pub struct Occur<T> {
    pub placeholder: String,
    pub spec: T,
}

#[derive(Debug, Clone)]
pub struct Template {
    pub text: String,
    pub regs: Vec<Occur<RegSpec>>,
    pub imms: Vec<Occur<ImmSpec>>,
}

pub fn parse_template(line: &str) -> Template {
    let mut text = line.to_string();
    let mut regs = Vec::<Occur<RegSpec>>::new();
    let mut imms = Vec::<Occur<ImmSpec>>::new();
    let mut reg_i = 0usize;
    let mut imm_i = 0usize;

    // Case-insensitive register class. Use literal '?' for wildcard tokens.
    let re_reg_any = Regex::new(r"(?i)([wx])\?").expect("re_reg_any compile"); // w? / x?
    let re_reg_rng = Regex::new(r"(?i)([wx])\[(\d+)\.\.(\d+)\]").expect("re_reg_rng compile"); // w[0..5]
    let re_reg_set = Regex::new(r"(?i)([wx])\{([0-9,]+)\}").expect("re_reg_set compile"); // w{0,1,2}
    let re_imm_any = Regex::new(r"#\?").expect("re_imm_any compile"); // #?
    let re_imm_rng = Regex::new(
        r"#range\((0x[0-9A-Fa-f]+|\d+)\.\.(0x[0-9A-Fa-f]+|\d+)(?:,(0x[0-9A-Fa-f]+|\d+))?\)",
    )
    .expect("re_imm_rng compile"); // #range(0..255[,step])
    let re_bm_any = Regex::new(r"#bm\?").expect("re_bm_any compile"); // #bm?

    fn apply<F>(
        text: &mut String,
        regs: &mut Vec<Occur<RegSpec>>,
        imms: &mut Vec<Occur<ImmSpec>>,
        re: &Regex,
        mut f: F,
    ) where
        F: FnMut(&regex::Captures) -> (String, Option<RegSpec>, Option<ImmSpec>),
    {
        loop {
            let caps_opt = re.captures(text);
            let caps = match caps_opt {
                Some(c) => c,
                None => break,
            };
            let (ph, reg_spec, imm_spec) = f(&caps);
            if let Some(m0) = caps.get(0) {
                text.replace_range(m0.start()..m0.end(), &ph);
            } else {
                break;
            }
            if let Some(rs) = reg_spec {
                regs.push(Occur {
                    placeholder: ph.clone(),
                    spec: rs,
                });
            }
            if let Some(is) = imm_spec {
                imms.push(Occur {
                    placeholder: ph.clone(),
                    spec: is,
                });
            }
        }
    }

    fn parse_u64(s: &str) -> Option<u64> {
        if s.starts_with("0x") || s.starts_with("0X") {
            u64::from_str_radix(&s[2..], 16).ok()
        } else {
            s.parse().ok()
        }
    }

    apply(&mut text, &mut regs, &mut imms, &re_bm_any, |_| {
        let ph = format!("{{{{IMM{}}}}}", {
            let x = imm_i;
            imm_i += 1;
            x
        });
        (ph.clone(), None, Some(ImmSpec::BitmaskAny))
    });
    apply(&mut text, &mut regs, &mut imms, &re_imm_rng, |c| {
        let lo = parse_u64(&c[1]).unwrap_or(0);
        let hi = parse_u64(&c[2]).unwrap_or(lo);
        let step = c
            .get(3)
            .and_then(|x| parse_u64(x.as_str()))
            .unwrap_or(1)
            .max(1);
        let ph = format!("{{{{IMM{}}}}}", {
            let x = imm_i;
            imm_i += 1;
            x
        });
        (ph.clone(), None, Some(ImmSpec::Range { lo, hi, step }))
    });
    apply(&mut text, &mut regs, &mut imms, &re_imm_any, |_| {
        let ph = format!("{{{{IMM{}}}}}", {
            let x = imm_i;
            imm_i += 1;
            x
        });
        (ph.clone(), None, Some(ImmSpec::Any))
    });
    apply(&mut text, &mut regs, &mut imms, &re_reg_rng, |c| {
        let reg_class = &c[1].to_ascii_uppercase();
        let is64 = reg_class == "X";
        let lo: u8 = c[2].parse().unwrap_or(0);
        let hi: u8 = c[3].parse().unwrap_or(lo);
        let (lo, hi) = if hi < lo { (hi, lo) } else { (lo, hi) };
        let ph = format!("{{{{REG{}}}}}", {
            let x = reg_i;
            reg_i += 1;
            x
        });
        (ph.clone(), Some(RegSpec::Range { is64, lo, hi }), None)
    });
    apply(&mut text, &mut regs, &mut imms, &re_reg_set, |c| {
        let reg_class = &c[1].to_ascii_uppercase();
        let is64 = reg_class == "X";
        let mut vals: Vec<u8> = c[2].split(',').filter_map(|t| t.parse().ok()).collect();
        vals.sort_unstable();
        vals.dedup();
        let ph = format!("{{{{REG{}}}}}", {
            let x = reg_i;
            reg_i += 1;
            x
        });
        (ph.clone(), Some(RegSpec::Set { is64, vals }), None)
    });
    apply(&mut text, &mut regs, &mut imms, &re_reg_any, |c| {
        let reg_class = &c[1].to_ascii_uppercase();
        let is64 = reg_class == "X";
        let ph = format!("{{{{REG{}}}}}", {
            let x = reg_i;
            reg_i += 1;
            x
        });
        (ph.clone(), Some(RegSpec::AnyGpr(is64)), None)
    });

    // Clamp register numbers to architectural max (X30/W30) to avoid later assembly failures.
    for r in &mut regs {
        match &mut r.spec {
            RegSpec::Range { lo, hi, .. } => {
                if *lo > 30 {
                    *lo = 30;
                }
                if *hi > 30 {
                    *hi = 30;
                }
            }
            RegSpec::Set { vals, .. } => {
                vals.retain(|v| *v <= 30);
                if vals.is_empty() {
                    vals.push(0);
                }
            }
            RegSpec::Fixed { num, .. } => {
                if *num > 30 {
                    *num = 30;
                }
            }
            _ => {}
        }
    }
    Template { text, regs, imms }
}

fn repl_once(hay: &str, placeholder: &str, with_: &str) -> String {
    if let Some(pos) = hay.find(placeholder) {
        let mut s = String::with_capacity(hay.len() - placeholder.len() + with_.len());
        s.push_str(&hay[..pos]);
        s.push_str(with_);
        s.push_str(&hay[pos + placeholder.len()..]);
        s
    } else {
        hay.to_string()
    }
}

fn base_reg_token(rs: &RegSpec) -> String {
    match rs {
        RegSpec::AnyGpr(true) => "X0".into(),
        RegSpec::AnyGpr(false) => "W0".into(),
        RegSpec::Range { is64: true, lo, .. } => format!("X{lo}"), // use lower bound as base to keep inside declared range
        RegSpec::Range {
            is64: false, lo, ..
        } => format!("W{lo}"),
        RegSpec::Set { is64: true, vals } => format!("X{}", vals.first().cloned().unwrap_or(0)),
        RegSpec::Set { is64: false, vals } => format!("W{}", vals.first().cloned().unwrap_or(0)),
        RegSpec::Fixed { is64, num } => {
            if *is64 {
                format!("X{num}")
            } else {
                format!("W{num}")
            }
        }
    }
}

fn base_imm_token(is: &ImmSpec) -> String {
    match is {
        ImmSpec::Any | ImmSpec::Range { .. } => "#0".into(),
        ImmSpec::Fixed(v) => format!("#{v}"),
        ImmSpec::BitmaskAny => "#0xFF00FF00FF00FF00".into(),
    }
}

pub fn make_r2_mask_for_a64_template<F>(t: &Template, assembler: F) -> Result<(String, String)>
where
    F: Fn(&str) -> Result<Vec<u8>>,
{
    let mnemonic = t.text.split_whitespace().next().unwrap_or("");
    let templ = t.text.clone();
    let mut base = templ.clone();
    for o in &t.regs {
        let rep = base_reg_token(&o.spec);
        while base.contains(&o.placeholder) {
            base = repl_once(&base, &o.placeholder, &rep);
        }
    }
    for o in &t.imms {
        let rep = base_imm_token(&o.spec);
        while base.contains(&o.placeholder) {
            base = repl_once(&base, &o.placeholder, &rep);
        }
    }
    let base_bytes = assembler(&base)
        .map_err(|e| anyhow::anyhow!("Base assemble '{base}' failed: {e}"))?;
    ensure!(base_bytes.len() == 4, "expect 32-bit A64 instruction");
    let base_u32 = u32::from_le_bytes(base_bytes.clone().try_into().unwrap());

    // Helper to generate candidate register tokens to toggle each bit
    fn reg_candidates(spec: &RegSpec) -> Vec<String> {
        let mut out = Vec::new();
        match spec {
            RegSpec::AnyGpr(is64) => {
                let prefix = if *is64 { 'X' } else { 'W' };
                // Cover each bit position plus a high value
                for v in [1u8, 2, 4, 8, 16, 30] {
                    out.push(format!("{prefix}{v}"));
                }
            }
            RegSpec::Range { is64, lo, hi } => {
                let prefix = if *is64 { 'X' } else { 'W' };
                // Try to toggle each bit individually within range
                for bit in 0..5 {
                    let v = lo.saturating_add(1 << bit);
                    if v <= *hi {
                        out.push(format!("{prefix}{v}"));
                    }
                }
                if *hi != *lo {
                    out.push(format!("{prefix}{hi}"));
                }
            }
            RegSpec::Set { is64, vals } => {
                let prefix = if *is64 { 'X' } else { 'W' };
                for v in vals.iter().skip(1) {
                    out.push(format!("{prefix}{v}"));
                }
            }
            RegSpec::Fixed { .. } => {}
        }
        out.sort();
        out.dedup();
        out
    }

    // Helper to generate candidate immediate tokens
    fn imm_candidates(spec: &ImmSpec, mnemonic: &str) -> Vec<String> {
        let mut out = Vec::new();
        match spec {
            ImmSpec::Any => {
                // Generic set hits low bits and high bits
                out.extend(["#1".to_string(), "#0xFF".to_string(), "#0xFFF".to_string()]);
                let m = mnemonic.to_ascii_lowercase();
                if m.starts_with("ldr")
                    || m.starts_with("str")
                    || m.starts_with("ldur")
                    || m.starts_with("stur")
                {
                    out.push("#0x100".into()); // exercise scaled field
                }
            }
            ImmSpec::Range { lo, hi, step, .. } => {
                let mut v = *lo;
                // sample first few values up to 8 steps to toggle lower bits
                for _ in 0..8 {
                    if v > *hi {
                        break;
                    }
                    out.push(format!("#{v}"));
                    v = v.saturating_add(*step);
                }
                if !out.iter().any(|s| s == &format!("#{hi}")) {
                    out.push(format!("#{hi}"));
                }
            }
            ImmSpec::BitmaskAny => {
                out.extend(["#0xFF".into(), "#0xFF00FF00FF00FF00".into()]);
            }
            ImmSpec::Fixed(_) => {}
        }
        out.sort();
        out.dedup();
        out
    }

    let mut varying: u32 = 0;
    // Register placeholders variation accumulation
    for o in &t.regs {
        let base_token = base_reg_token(&o.spec);
        let candidates = reg_candidates(&o.spec);
        for cand in candidates {
            if cand == base_token {
                continue;
            }
            let mut asm_line = templ.clone();
            // replace this placeholder with candidate, others with base
            for r in &t.regs {
                let rep = if r.placeholder == o.placeholder {
                    cand.clone()
                } else {
                    base_reg_token(&r.spec)
                };
                while asm_line.contains(&r.placeholder) {
                    asm_line = repl_once(&asm_line, &r.placeholder, &rep);
                }
            }
            for im in &t.imms {
                // base imm tokens
                let rep = base_imm_token(&im.spec);
                while asm_line.contains(&im.placeholder) {
                    asm_line = repl_once(&asm_line, &im.placeholder, &rep);
                }
            }
            if let Ok(bytes) = assembler(&asm_line) {
                if bytes.len() == 4 {
                    let val = u32::from_le_bytes(bytes.try_into().unwrap());
                    varying |= base_u32 ^ val;
                }
            }
        }
    }
    // Immediate placeholders variation accumulation
    for o in &t.imms {
        let base_token = base_imm_token(&o.spec);
        let candidates = imm_candidates(&o.spec, mnemonic);
        for cand in candidates {
            if cand == base_token {
                continue;
            }
            let mut asm_line = templ.clone();
            for r in &t.regs {
                // all regs base tokens
                let rep = base_reg_token(&r.spec);
                while asm_line.contains(&r.placeholder) {
                    asm_line = repl_once(&asm_line, &r.placeholder, &rep);
                }
            }
            for im in &t.imms {
                let rep = if im.placeholder == o.placeholder {
                    cand.clone()
                } else {
                    base_imm_token(&im.spec)
                };
                while asm_line.contains(&im.placeholder) {
                    asm_line = repl_once(&asm_line, &im.placeholder, &rep);
                }
            }
            if let Ok(bytes) = assembler(&asm_line) {
                if bytes.len() == 4 {
                    let val = u32::from_le_bytes(bytes.try_into().unwrap());
                    varying |= base_u32 ^ val;
                }
            }
        }
    }

    // Heuristic: for branch immediates (B/BL), imm26 field varies entirely when wildcard is present
    let has_imm_wildcard = t.imms.iter().any(|im| matches!(im.spec, ImmSpec::Any | ImmSpec::Range { .. } | ImmSpec::BitmaskAny));
    if has_imm_wildcard {
        let m = mnemonic.to_ascii_lowercase();
        if m == "bl" || m == "b" { 
            varying |= 0x03FF_FFFF; // 26-bit immediate field for branch instructions
        }
    }
    let stable = !varying;
    
    // Generate pattern:mask in little-endian byte order (LSB first)
    let base_bytes = base_u32.to_le_bytes();
    let stable_bytes = stable.to_le_bytes();
    let mut pat = String::with_capacity(8);
    let mut msk = String::with_capacity(8);
    
    for i in 0..4 {
        let b = base_bytes[i];
        let mb = stable_bytes[i];
        let high = (b >> 4) & 0xF;
        let high_m = (mb >> 4) & 0xF;
        let low = b & 0xF;
        let low_m = mb & 0xF;
        pat.push(std::char::from_digit((high & high_m) as u32, 16).unwrap());
        pat.push(std::char::from_digit((low & low_m) as u32, 16).unwrap());
        msk.push(std::char::from_digit(high_m as u32, 16).unwrap());
        msk.push(std::char::from_digit(low_m as u32, 16).unwrap());
    }
    Ok((pat, msk))
}

/// Helper function to create a Keystone assembler for AArch64
#[cfg(feature = "keystone")]
pub fn create_keystone_assembler() -> Result<impl Fn(&str) -> Result<Vec<u8>>> {
    let engine = Keystone::new(Arch::ARM64, Mode::LITTLE_ENDIAN)
        .map_err(|e| anyhow::anyhow!("Failed to create Keystone engine: {}", e))?;
    
    Ok(move |asm: &str| {
        engine.asm(asm.to_string(), 0)
            .map(|result| result.bytes)
            .map_err(|e| anyhow::anyhow!("Assembly failed: {}", e))
    })
}

/// Convenience function to generate pattern:mask using Keystone assembler
#[cfg(feature = "keystone")]
pub fn make_r2_mask_with_keystone(template: &str) -> Result<(String, String)> {
    let parsed = parse_template(template);
    let assembler = create_keystone_assembler()?;
    make_r2_mask_for_a64_template(&parsed, assembler)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_assembler(asm: &str) -> Result<Vec<u8>> {
        // Mock assembler for testing - returns simple patterns
        match asm {
            "BL #0" => Ok(vec![0x94, 0x00, 0x00, 0x00]),
            "BL #4" => Ok(vec![0x94, 0x00, 0x00, 0x01]),
            _ => Ok(vec![0x94, 0x00, 0x00, 0x00]),
        }
    }

    #[test]
    fn test_parse_bl_wildcard() {
        let t = parse_template("BL #?");
        assert_eq!(t.imms.len(), 1);
        let (pat, msk) = make_r2_mask_for_a64_template(&t, mock_assembler).unwrap();
        assert!(pat.len() == 8 && msk.len() == 8);
    }
}
