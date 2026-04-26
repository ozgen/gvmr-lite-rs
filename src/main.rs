#[tokio::main]
async fn main() {
    gvmr_lite_rs::run().await.expect("application failed");
}
