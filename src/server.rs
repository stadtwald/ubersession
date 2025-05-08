use ed25519_dalek::SigningKey;
use std::collections::HashSet;
use std::net::SocketAddr;

#[derive(Clone, Debug)]
pub struct Server {
    listen: SocketAddr,
    signing_key: SigningKey,
    token_expiry: u32,
    token_request_expiry: u32,
    verbose_workflow: bool,
    no_plain_html: bool,
    url_prefix: String,
    authority: String,
    domains: HashSet<String>,
    cookie: String
}

impl Server {
    pub fn try_init_from_serve_opts(opts: crate::cli::serve::Serve) -> anyhow::Result<Self> {
        let cookie = opts.cookie.trim();
        let mut url_prefix = opts.url_prefix.trim().to_owned();
        if opts.token_expiry < 60 {
            Err(anyhow::anyhow!("Token expiry must be at least a minute"))
        } else if opts.token_request_expiry < 10 {
            Err(anyhow::anyhow!("Token request expirty must be at least ten seconds"))
        } else if cookie.len() < 1 {
            Err(anyhow::anyhow!("Cookie name must not be empty"))
        } else if !url_prefix.starts_with('/') {
            Err(anyhow::anyhow!("URL prefix must start with a forward slash (/)"))
        } else {
            let raw_input = std::fs::read(&opts.private_key_file)?;
            let keypair_description: crate::wire::Keypair = serde_json::from_slice(&raw_input)?;
            let signing_key = keypair_description.try_loading_signing_key()?;
            
            if !url_prefix.ends_with('/') {
                url_prefix.push('/');
            }

            let authority = opts.authority.trim().to_ascii_lowercase();
            let mut domains = HashSet::new();
            domains.insert(authority.clone());

            for domain in opts.domains {
                domains.insert(domain.trim().to_ascii_lowercase());
            }

            Ok(Self {
                listen: opts.listen,
                signing_key: signing_key,
                token_expiry: opts.token_expiry,
                token_request_expiry: opts.token_request_expiry,
                verbose_workflow: opts.verbose_workflow,
                no_plain_html: opts.no_plain_html,
                url_prefix: url_prefix,
                authority: authority,
                domains: domains,
                cookie: cookie.to_owned()
            })
        }
    }

    pub async fn serve(&self) -> anyhow::Result<()> {
        Ok(())
    }
}


