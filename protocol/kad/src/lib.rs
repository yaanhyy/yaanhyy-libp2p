pub mod protocol;
pub mod addresses;
pub mod dht;
pub mod record;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
