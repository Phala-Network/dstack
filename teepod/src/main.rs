//! Teepod VM Supervisor
//!
//! This is the main file for the Teepod VM supervisor. It provides a web interface
//! using Rocket to manage virtual machines (VMs).
//!
//! # Features
//!
//! - Restarts all VMs in `~/.teepod/vm/` on startup if not running
//! - Starts an HTTP server using Rocket to provide APIs
//! - Starts a web interface using Yew for VM management
//! - Leverages libvirt/libvirt-daemon for VM management
//! - Distinguishes between user-created and supervisor-created VMs
//! - Creates VMs with the prefix `teepod-created-vm-`
//! - Stores VM metadata in `~/.teepod/vm/`
//! - Maintains VM images in `~/.teepod/image/`
//! - Monitors and restarts VMs if they stop running
//!
//! # API Endpoints
//!
//! - `POST /vm/create`: Create a new VM
//! - `DELETE /vm/delete?id=`: Delete a VM
//! - `GET /vm/status?id=`: Get the status of a VM
//! - `GET /vm/logs?id=`: Get the logs of a VM
//! - `GET /vm/list`: List all VMs
//!
//! The supervisor itself is stateless, relying on libvirt-daemon for VM management.

use rocket::launch;
use teepod::{routes, App};

#[launch]
fn rocket() -> _ {
    tracing_subscriber::fmt::init();

    // find qemu-system-x86_64
    let qemu_bin = std::process::Command::new("which")
        .arg("qemu-system-x86_64")
        .output()
        .expect("failed to find qemu-system-x86_64")
        .stdout;
    let qemu_bin =
        String::from_utf8(qemu_bin).expect("failed to convert qemu-system-x86_64 to string");

    let app = App::new(qemu_bin);

    rocket::build().mount("/", routes()).manage(app)
}
