pub const NEG: i32 = (-1 * 0x7fffffff) - 1;

pub trait TargetMemory {
    fn write_data(&mut self, content: &[u8], target_addr: u32);

    fn write_i32(&mut self, target_addr: u32, value: i32);
    fn write_u32(&mut self, target_addr: u32, value: u32);

    fn read_i32(&self, target_addr: u32) -> i32;
    fn read_u32(&self, target_addr: u32) -> u32;

    fn read_u8(&self, target_addr: u32) -> u8;
}

pub fn write_u32(content: &mut [u8], offset: usize, value: u32) {
    content[offset] = (value & 0xff) as u8;
    content[offset + 1] = ((value >> 8) & 0xff) as u8;
    content[offset + 2] = ((value >> 16) & 0xff) as u8;
    content[offset + 3] = ((value >> 24) & 0xff) as u8;
}

pub fn read_u16(content: &[u8], offset: usize) -> u16 {
    (content[offset] as u16) | ((content[offset + 1] as u16) << 8)
}

pub fn read_u24(content: &[u8], offset: usize) -> u32 {
    read_u16(content, offset) as u32 | ((content[offset + 2] as u32) << 16)
}

pub fn read_u32(content: &[u8], offset: usize) -> u32 {
    read_u24(content, offset) | ((content[offset + 3] as u32) << 24)
}

pub fn read_i32(content: &[u8], offset: usize) -> i32 {
    let first_24 = read_u24(content, offset) as i32;
    let msb = content[offset + 3] as i32;
    if (msb & 0x80) != 0 {
        NEG + (first_24 | ((msb & 0x7f) << 24))
    } else {
        first_24 | (msb << 24)
    }
}
