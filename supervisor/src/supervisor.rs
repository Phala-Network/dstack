use crate::process::{Process, ProcessConfig, ProcessInfo};
use anyhow::{bail, Context, Result};
use dashmap::DashMap;

#[derive(Clone)]
pub struct Supervisor {
    pub processes: DashMap<String, Process>,
}

impl Supervisor {
    pub fn new() -> Self {
        Self {
            processes: DashMap::new(),
        }
    }

    pub fn deploy(&self, config: ProcessConfig) -> Result<()> {
        let id = config.id.clone();
        if id.is_empty() {
            return Err(anyhow::anyhow!("Process ID is empty"));
        }
        let process = Process::new(config);
        process.start()?;
        self.processes.insert(id, process);
        Ok(())
    }

    pub fn start(&self, id: &str) -> Result<()> {
        let process = self.processes.get(id).context("Process not found")?;
        process.start()
    }

    pub fn stop(&self, id: &str) -> Result<()> {
        let process = self.processes.get(id).context("Process not found")?;
        process.stop()
    }

    pub fn remove(&self, id: &str) -> Result<()> {
        let process = self.processes.get(id).context("Process not found")?;
        if process.is_started() {
            bail!("Process is started");
        }
        if process.is_running() {
            bail!("Process is running");
        }
        drop(process);
        self.processes.remove(id);
        Ok(())
    }

    pub fn list(&self) -> Vec<ProcessInfo> {
        self.processes
            .iter()
            .map(|pair| pair.value().info())
            .collect::<Vec<_>>()
    }

    pub fn info(&self, id: &str) -> Option<ProcessInfo> {
        self.processes.get(id).map(|process| process.info())
    }
}
