#[tokio::main]
async fn main() {
    gvmr_server::run().await.expect("application failed");
}
