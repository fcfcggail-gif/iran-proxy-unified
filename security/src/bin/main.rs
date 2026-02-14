use iran_proxy_security::{SecurityProcessor, SecurityConfig};
use log::info;

#[tokio::main]
async fn main() {
    env_logger::init();

    info!("Iran Proxy Security Module - Starting");

    // Create default security processor
    match SecurityProcessor::new() {
        Ok(processor) => {
            info!("Security processor initialized successfully");
            info!("Configuration: {:?}", processor.config());

            // Example usage
            let test_data = b"Example proxy traffic data";

            match processor.process_outgoing(test_data) {
                Ok(processed) => {
                    info!("Successfully processed outgoing traffic");
                    info!("Original size: {}, Processed size: {}", test_data.len(), processed.len());
                }
                Err(e) => {
                    eprintln!("Error processing traffic: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to initialize security processor: {}", e);
        }
    }

    info!("Iran Proxy Security Module - Shutdown");
}
