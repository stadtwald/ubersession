use ed25519_dalek::SigningKey;
use std::net::SocketAddr;

#[derive(Clone, Debug)]
pub struct ServerParameters {
    listen: SocketAddr,
    signing_key: SigningKey,
    token_expiry: u32,
    token_request_expiry: u32,
    verbose_workflow: bool,
    no_plain_html: bool,
    url_prefix: String,
    authority: String,
    domains: Vec<String>,
    cookie: String
}

impl ServerParameters {
    pub fn try_load_from_serve_opts(opts: crate::cli::serve::Serve) -> anyhow::Result<Self> {
        let cookie = opts.cookie.trim();
        let mut url_prefix = opts.url_prefix.trim().to_owned();
        if opts.token_expiry < 60 {
            Err(anyhow::anyhow!("Token expiry must be at least a minute"))
        } else if opts.token_request_expiry < 10 {
            Err(anyhow::anyhow!("Token request expirty must be at least ten seconds"))
        } else if cookie.len() < 1 {
            Err(anyhow::anyhow!("Cookie name must not be empty"))
        } else if url_prefix.starts_with('/') {
            Err(anyhow::anyhow!("URL prefix must start with a forward slash (/)"))
        } else {
            let raw_input = std::fs::read(&opts.private_key_file)?;
            let keypair_description: crate::wire::Keypair = serde_json::from_slice(&raw_input)?;
            let signing_key = keypair_description.try_loading_signing_key()?;
            
            if !url_prefix.ends_with('/') {
                url_prefix.push('/');
            }

            let mut domains = opts.domains;

            if !domains.contains(&opts.authority) {
                domains.push(opts.authority.clone());
            }

            Ok(ServerParameters {
                listen: opts.listen,
                signing_key: signing_key,
                token_expiry: opts.token_expiry,
                token_request_expiry: opts.token_request_expiry,
                verbose_workflow: opts.verbose_workflow,
                no_plain_html: opts.no_plain_html,
                url_prefix: url_prefix,
                authority: opts.authority,
                domains: domains,
                cookie: cookie.to_owned()
            })
        }
    }
}

pub async fn serve(_parameters: ServerParameters) -> anyhow::Result<()> {
    Ok(())
}

