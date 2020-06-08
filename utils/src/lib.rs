use env_logger;
use log::debug;

pub fn init_log(log_level: &str){
    use std::io::Write;
    use chrono::Local;
    let env = env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV,log_level);
    env_logger::Builder::from_env(env).format(|buf,record|{
        writeln!(
            buf,
            "{} {} [{}:{}] {} {}",
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            record.level(),
            record.module_path().unwrap_or("<unnamed>"),
            record.line().unwrap_or(0),
            record.target(),
            &record.args()
        )
    }).init();
    debug!("log config success")
}
