use futures::Future;
use futures::Stream;
use reqwest::async::Client;
use reqwest::header::USER_AGENT;

use config::Config;
use std::sync::Arc;
use yubicoerror::YubicoError;
use {build_request, Result};

pub fn verify_async<S>(
    otp: S,
    config: Config,
) -> Result<impl Future<Item = (), Error = YubicoError>>
where
    S: Into<String>,
{
    AsyncVerifier::new(config)?.verify(otp)
}

pub struct AsyncVerifier {
    client: Client,
    config: Config,
}

impl AsyncVerifier {
    pub fn new(config: Config) -> Result<AsyncVerifier> {
        let client = Client::builder().timeout(config.request_timeout).build()?;

        Ok(AsyncVerifier { client, config })
    }

    pub fn verify<S>(&self, otp: S) -> Result<impl Future<Item = (), Error = YubicoError>>
    where
        S: Into<String>,
    {
        let request = build_request(otp, &self.config)?;
        let request = Arc::new(request); // Arc because we need the future to be Send.

        let mut urls = vec![];
        for api_host in &self.config.api_hosts {
            let url = request.build_url(api_host);

            urls.push(url);
        }

        let req_futures = urls.iter().map(|url| {
            let request = request.clone();

            self.request(&url).and_then(move |raw_response| {
                request.response_verifier.verify_response(raw_response)
            })
        });

        Ok(futures::stream::futures_unordered(req_futures)
            .then(|result| {
                // Interrupt the stream if: the OTP is valid or an error different than an HTTP error or a ReplayedRequest is returned.
                // This is inspired by the official C client.
                match result {
                    // Wrap these in Ok to continue the stream.
                    Err(YubicoError::ReplayedRequest) => Ok(YubicoError::ReplayedRequest),
                    Err(YubicoError::HTTPStatusCode(code)) => Ok(YubicoError::HTTPStatusCode(code)),
                    // Wrap these in Err to interrupt the stream.
                    Err(err) => Err(Err(err)),
                    Ok(()) => Err(Ok(())),
                }
            })
            .collect()
            .then(|result| match result {
                Ok(less_relevant_errs) => Err(YubicoError::MultipleErrors(less_relevant_errs)),
                Err(Ok(())) => Ok(()),
                Err(Err(err)) => Err(err),
            }))
    }

    fn request(&self, url: &str) -> impl Future<Item = String, Error = YubicoError> {
        let request = self
            .client
            .get(url)
            .header(USER_AGENT, self.config.user_agent.clone());

        request
            .send()
            .map_err(YubicoError::from)
            .then(|result| {
                let response = result?;
                let status_code = response.status();

                if status_code.is_success() {
                    Ok(response)
                } else {
                    Err(YubicoError::HTTPStatusCode(status_code))
                }
            })
            .and_then(|response| response.into_body().concat2().map_err(YubicoError::from))
            .map(|chunks| {
                // TODO This implies a copy.
                String::from_utf8_lossy(&*chunks).to_string()
            })
    }
}
