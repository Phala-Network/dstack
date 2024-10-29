use std::pin::pin;

use tokio::{
    select,
    sync::broadcast::Receiver,
    time::{self, Duration},
};
use tracing::{error, info};

pub fn start_proxy(config_file: String, mut reconfigure_rx: Receiver<()>) {
    tokio::spawn(async move {
        info!("starting proxy");
        loop {
            let todo = "better config hot reloading";
            let mut proxy = pin!(rproxy::run(&config_file));
            select! {
                msg = reconfigure_rx.recv() => {
                    match msg {
                        Ok(_) => info!("reconfiguring proxy"),
                        Err(_) => {
                            error!("reconfigure channel closed");
                            break;
                        }
                    }
                }
                result = &mut proxy => {
                    if let Err(e) = result {
                        error!("proxy failed: {}", e);
                        time::sleep(Duration::from_secs(5)).await;
                    }
                    info!("proxy restarted");
                }
            }
        }
    });
}
