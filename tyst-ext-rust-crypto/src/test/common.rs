pub fn init_logger() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Debug)
        //.filter(Some("rustls"), log::LevelFilter::Info)
        //.filter(Some("ureq"), log::LevelFilter::Info)
        .try_init();
}
