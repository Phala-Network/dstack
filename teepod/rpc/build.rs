fn main() {
    let out_dir = "./src/generated";

    let mut builder = prpc_build::configure()
        .out_dir(out_dir)
        .mod_prefix("super::")
        .disable_package_emission();
    builder = builder.type_attribute(".teepod", "#[::prpc::serde_helpers::prpc_serde_bytes]");
    builder = builder.type_attribute(
        ".teepod",
        "#[derive(::serde::Serialize, ::serde::Deserialize)]",
    );
    builder = builder.field_attribute(".teepod", "#[serde(default)]");
    builder
        .compile(&["teepod_rpc.proto"], &["./proto"])
        .expect("failed to compile proto files");
}