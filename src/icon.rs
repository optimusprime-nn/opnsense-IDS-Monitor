//! The app's shield icon, drawn in code (window, tray, and toast icons).

/// Shield colour; `alert` gives the red variant the tray shows when there are open critical/high findings.
pub fn rgba(size: u32, alert: bool) -> Vec<u8> {
    let (r, g, b) = if alert { (0xd9, 0x2d, 0x20) } else { (0x1f, 0x6f, 0xeb) };
    let mut px = vec![0u8; (size * size * 4) as usize];
    let k = size as f32 / 32.0;
    for y in 0..size {
        let yy = (y as f32 + 0.5) / k;
        if !(2.0..31.0).contains(&yy) {
            continue;
        }
        let half = if yy < 17.0 { 13.0 } else { 13.0 - (yy - 17.0) * 13.0 / 14.0 };
        for x in 0..size {
            let xx = (x as f32 + 0.5) / k;
            let inside = (xx - 16.0).abs() <= half;
            if !inside {
                continue;
            }
            let cross = ((14.0..18.0).contains(&xx) && (7.0..23.0).contains(&yy))
                || ((9.0..23.0).contains(&xx) && (12.0..16.0).contains(&yy));
            let i = ((y * size + x) * 4) as usize;
            let c = if cross { [255, 255, 255] } else { [r, g, b] };
            px[i..i + 4].copy_from_slice(&[c[0], c[1], c[2], 255]);
        }
    }
    px
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
        }
    }
    !c
}

/// Minimal PNG encoder (uncompressed deflate) - enough for a small icon file.
pub fn png(size: u32) -> Vec<u8> {
    let px = rgba(size, false);
    let mut raw = Vec::with_capacity(px.len() + size as usize);
    for row in px.chunks(size as usize * 4) {
        raw.push(0); // filter: none
        raw.extend_from_slice(row);
    }
    let mut z = vec![0x78, 0x01];
    let chunks: Vec<&[u8]> = raw.chunks(65535).collect();
    for (i, c) in chunks.iter().enumerate() {
        z.push(if i + 1 == chunks.len() { 1 } else { 0 });
        z.extend_from_slice(&(c.len() as u16).to_le_bytes());
        z.extend_from_slice(&(!(c.len() as u16)).to_le_bytes());
        z.extend_from_slice(c);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for &x in &raw {
        a = (a + x as u32) % 65521;
        b = (b + a) % 65521;
    }
    z.extend_from_slice(&((b << 16) | a).to_be_bytes());

    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut chunk = |kind: &[u8], data: &[u8]| {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        let mut body = kind.to_vec();
        body.extend_from_slice(data);
        out.extend_from_slice(&body);
        out.extend_from_slice(&crc32(&body).to_be_bytes());
    };
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&size.to_be_bytes());
    ihdr.extend_from_slice(&size.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit RGBA
    chunk(b"IHDR", &ihdr);
    chunk(b"IDAT", &z);
    chunk(b"IEND", &[]);
    out
}

/// .ico with PNG-compressed entries (used to regenerate assets/ipswatch.ico).
pub fn ico(sizes: &[u32]) -> Vec<u8> {
    let pngs: Vec<Vec<u8>> = sizes.iter().map(|&s| png(s)).collect();
    let mut out = vec![0, 0, 1, 0];
    out.extend_from_slice(&(sizes.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * sizes.len() as u32;
    for (s, p) in sizes.iter().zip(&pngs) {
        let d = (*s % 256) as u8;
        out.extend_from_slice(&[d, d, 0, 0, 1, 0, 32, 0]);
        out.extend_from_slice(&(p.len() as u32).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        offset += p.len() as u32;
    }
    for p in pngs {
        out.extend_from_slice(&p);
    }
    out
}
