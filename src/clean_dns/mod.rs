#[derive(Debug, Clone)]
#[repr(C)]
pub struct Query {
    pub count_block: u64,
}

impl Query {
    pub fn new() -> Query {
        Query {
            count_block: 0,
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct Connection {
    pub source_ip: u32,
    pub allowed: u32,
}
