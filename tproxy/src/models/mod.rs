use crate::config::PortMap;
use rinja::Template;
use serde::{Deserialize, Serialize};
use std::{
    collections::{btree_map::Iter, BTreeMap},
    net::Ipv4Addr,
};

pub struct MapValues<'a, K, V>(pub &'a BTreeMap<K, V>);
impl<'a, K, V> Copy for MapValues<'a, K, V> {}
impl<'a, K, V> Clone for MapValues<'a, K, V> {
    fn clone(&self) -> Self {
        MapValues(self.0)
    }
}
impl<'a, K, V> From<&'a BTreeMap<K, V>> for MapValues<'a, K, V> {
    fn from(map: &'a BTreeMap<K, V>) -> Self {
        MapValues(map)
    }
}

impl<'a, K, V> MapValues<'a, K, V> {
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

pub struct MapValuesIter<'a, K, V>(Iter<'a, K, V>);

impl<'a, K, V> IntoIterator for MapValues<'a, K, V> {
    type Item = &'a V;
    type IntoIter = MapValuesIter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        MapValuesIter(self.0.iter())
    }
}

impl<'a, K, V> Iterator for MapValuesIter<'a, K, V> {
    type Item = &'a V;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(_, v)| v)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostInfo {
    pub id: String,
    pub ip: Ipv4Addr,
    pub public_key: String,
}

#[derive(Template)]
#[template(path = "wg.conf", escape = "none")]
pub struct WgConf<'a> {
    pub private_key: &'a str,
    pub listen_port: u16,
    pub peers: MapValues<'a, String, HostInfo>,
}

#[derive(Template)]
#[template(path = "rproxy.yaml", escape = "none")]
pub struct RProxyConf<'a> {
    pub portmap: &'a [PortMap],
    pub peers: MapValues<'a, String, HostInfo>,
    pub cert_chain: &'a str,
    pub cert_key: &'a str,
    pub base_domain: &'a str,
}
