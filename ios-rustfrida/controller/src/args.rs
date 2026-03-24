use clap::Parser;

#[derive(Debug, Parser)]
#[command(author, version, about = "iOS jailbreak edition of rustFrida controller")]
pub struct Args {
    #[arg(long, value_name = "PID")]
    pub pid: Option<i32>,

    #[arg(long, value_name = "BUNDLE_ID")]
    pub bundle_id: Option<String>,

    #[arg(long, requires = "bundle_id")]
    pub spawn: bool,

    #[arg(long, value_name = "SHELL", requires = "spawn")]
    pub spawn_command: Option<String>,

    #[arg(long, value_name = "FILE")]
    pub script: Option<String>,

    #[arg(
        long,
        value_name = "COMMAND",
        conflicts_with_all = ["list_images", "list_images_json", "preflight_only", "preflight_json", "inject_json"]
    )]
    pub command: Option<String>,

    #[arg(long, requires = "command")]
    pub command_json: bool,

    #[arg(long, value_name = "PATH")]
    pub socket_path: Option<String>,

    #[arg(long)]
    pub list_images: bool,

    #[arg(long, requires = "list_images")]
    pub list_images_json: bool,

    #[arg(long)]
    pub preflight_only: bool,

    #[arg(long, requires = "preflight_only")]
    pub preflight_json: bool,

    #[arg(long, conflicts_with_all = ["list_images", "list_images_json", "preflight_only", "preflight_json"])]
    pub inject_json: bool,

    #[arg(long, value_name = "PATH")]
    pub agent_path: Option<String>,

    #[arg(long, default_value = "ios_agent_entry")]
    pub entry_symbol: String,

    #[arg(long, default_value_t = 15)]
    pub connect_timeout: u64,
}
