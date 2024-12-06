use super::*;
use crate::config::{load_config_figment, Config};

fn create_test_state() -> AppState {
    let figment = load_config_figment(None);
    let config = figment.focus("core").extract::<Config>().unwrap();
    AppState::new(config).expect("failed to create app state")
}

#[test]
fn test_empty_config() {
    let state = create_test_state();
    let wg_config = state.lock().generate_wg_config().unwrap();
    insta::assert_snapshot!(wg_config);
}

#[test]
fn test_config() {
    let state = create_test_state();
    let mut info = state
        .lock()
        .new_client_by_id("test-id-0", "app-id-0", "test-pubkey-0")
        .unwrap();

    info.reg_time = SystemTime::UNIX_EPOCH;
    insta::assert_debug_snapshot!(info);
    let mut info1 = state
        .lock()
        .new_client_by_id("test-id-1", "app-id-1", "test-pubkey-1")
        .unwrap();
    info1.reg_time = SystemTime::UNIX_EPOCH;
    insta::assert_debug_snapshot!(info1);
    let wg_config = state.lock().generate_wg_config().unwrap();
    insta::assert_snapshot!(wg_config);
}
