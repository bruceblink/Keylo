use keylo::config::Config;
use keylo::db;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    keylo::config::load_dotenv();

    let config = Config::from_env();
    let pool = db::init_db_pool(&config.database_url).await?;
    db::run_migrations(&pool).await?;
    println!("Migrations completed successfully!");
    Ok(())
}
