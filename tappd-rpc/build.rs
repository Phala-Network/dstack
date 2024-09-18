fn main() {
    let out_dir = "./src/generated";

    let mut builder = prpc_build::configure()
        .out_dir(out_dir)
        .mod_prefix("super::")
        .disable_package_emission();
    builder = builder.type_attribute(".tappd", "#[::prpc::serde_helpers::prpc_serde_bytes]");
    builder = builder.type_attribute(
        ".tappd",
        "#[derive(::serde::Serialize, ::serde::Deserialize)]",
    );
    builder = builder.field_attribute(".tappd", "#[serde(default)]");
    builder
        .compile(&["tappd_rpc.proto"], &["./proto"])
        .expect("failed to compile proto files");
}
