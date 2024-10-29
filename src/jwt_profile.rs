use std::{fmt::Display, marker::PhantomData, time::Duration};

use crate::{
    helpers::Timestamp,
    jwt::{JsonWebToken, JsonWebTokenJsonPayloadSerde},
    AdditionalClaims, Audience, AuthDisplay, AuthPrompt, GenderClaim, JsonWebKey,
    JsonWebTokenError, JweContentEncryptionAlgorithm, JwsSigningAlgorithm, PrivateSigningKey,
    TokenResponse,
};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use oauth2::{
    ClientCredentialsTokenRequest, EndpointSet, EndpointState, ErrorResponse, RevocableToken,
    TokenIntrospectionResponse,
};
use rand::{thread_rng, Rng};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use std::fmt::Debug;

///
/// Additional claims beyond the set of Standard Claims defined by OpenID Connect Core.
///
pub trait AdditionalClientAuthTokenClaims: Debug + DeserializeOwned + Serialize + 'static {}

///
/// No additional claims.
///
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
// In order to support serde flatten, this must be an empty struct rather than an empty
// tuple struct.
pub struct EmptyAdditionalClientAuthTokenClaims {}
impl AdditionalClientAuthTokenClaims for EmptyAdditionalClientAuthTokenClaims {}

/// FIXME: documentation
#[serde_as]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ClientAuthTokenClaims<AC> {
    #[serde(rename = "iss")]
    issuer: String,

    #[serde(rename = "sub")]
    subject: String,

    #[serde(rename = "aud")]
    audience: Audience,

    #[serde_as(as = "Timestamp")]
    #[serde(rename = "exp")]
    expiration: DateTime<Utc>,

    #[serde_as(as = "Option<Timestamp>")]
    #[serde(rename = "nbf", default, skip_serializing_if = "Option::is_none")]
    not_before: Option<DateTime<Utc>>,

    #[serde_as(as = "Option<Timestamp>")]
    #[serde(rename = "iat", default, skip_serializing_if = "Option::is_none")]
    issued_at: Option<DateTime<Utc>>,

    #[serde(rename = "jti", default, skip_serializing_if = "Option::is_none")]
    jwt_id: Option<ClientAuthTokenId>,

    #[serde(bound = "AC: AdditionalClientAuthTokenClaims")]
    #[serde(flatten)]
    additional_claims: AC,
}

new_type![
    ///
    /// Set of authentication methods or procedures that are considered to be equivalent to each
    /// other in a particular context.
    ///
    #[derive(Deserialize, Serialize)]
    ClientAuthTokenId(String)
];
impl ClientAuthTokenId {
    ///
    /// Generate a new random, base64-encoded 128-bit CSRF token.
    ///
    pub fn new_random() -> Self {
        ClientAuthTokenId::new_random_len(16)
    }
    ///
    /// Generate a new random, base64-encoded ClientAuthTokenId of the specified length.
    ///
    /// # Arguments
    ///
    /// * `num_bytes` - Number of random bytes to generate, prior to base64-encoding.
    ///
    pub fn new_random_len(num_bytes: u32) -> Self {
        let random_bytes: Vec<u8> = (0..num_bytes).map(|_| thread_rng().gen::<u8>()).collect();
        ClientAuthTokenId::new(BASE64_URL_SAFE_NO_PAD.encode(random_bytes))
    }
}

impl<
        AC,
        AD,
        GC,
        JE,
        K,
        P,
        TE,
        TR,
        TIR,
        RT,
        TRE,
        HasAuthUrl,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
        HasUserInfoUrl,
    >
    crate::Client<
        AC,
        AD,
        GC,
        JE,
        K,
        P,
        TE,
        TR,
        TIR,
        RT,
        TRE,
        HasAuthUrl,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
        EndpointSet,
        HasUserInfoUrl,
    >
where
    // AC: AdditionalClientAuthTokenClaims,
    AC: AdditionalClaims,
    AD: AuthDisplay,
    GC: GenderClaim,
    JE: JweContentEncryptionAlgorithm<
        KeyType = <K::SigningAlgorithm as JwsSigningAlgorithm>::KeyType,
    >,
    K: JsonWebKey,
    P: AuthPrompt,
    TE: ErrorResponse + 'static,
    TR: TokenResponse<AC, GC, JE, K::SigningAlgorithm>,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
    HasAuthUrl: EndpointState,
    HasDeviceAuthUrl: EndpointState,
    HasIntrospectionUrl: EndpointState,
    HasRevocationUrl: EndpointState,
    HasUserInfoUrl: EndpointState,
{
    /// FIXME: documentation
    pub fn client_auth_token_builder<S, JS, RF, ATC>(
        &self,
        signing_key: S,
        signing_algo: JS,
        duration: Duration,
        jwt_id_method: RF,
        additional_claims: ATC,
    ) -> ClientAuthTokenBuilder<ATC, JE, JS, K, RF, S>
    where
        JS: JwsSigningAlgorithm<KeyType = JE::KeyType>,
        RF: FnOnce() -> ClientAuthTokenId,
        ATC: AdditionalClientAuthTokenClaims,
        S: PrivateSigningKey,
        S::VerificationKey: JsonWebKey<SigningAlgorithm = JS>,
    {
        ClientAuthTokenBuilder::new(
            self.client_id.to_string(),
            self.client_id.to_string(),
            Audience::new(self.oauth2_client.token_uri().to_string()),
            signing_key,
            signing_algo,
            duration,
            jwt_id_method,
            additional_claims,
        )
    }

    /// FIXME: documentation
    pub fn exchange_client_credential_with_auth_token<ATC, JS>(
        &self,
        token: ClientAuthToken<ATC, JE, JS>,
    ) -> Result<ClientCredentialsTokenRequest<TE, TR>, JsonWebTokenError>
    where
        JS: JwsSigningAlgorithm<KeyType = JE::KeyType>,
        ATC: AdditionalClientAuthTokenClaims,
    {
        let ccrt = self
            .exchange_client_credentials()
            .add_extra_param(
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            )
            .add_extra_param("client_assertion", token.to_string());

        Ok(ccrt)
    }
}

/// FIXME: documentation
pub struct ClientAuthTokenBuilder<
    AC: AdditionalClientAuthTokenClaims,
    JE: JweContentEncryptionAlgorithm<KeyType = JS::KeyType>,
    JS: JwsSigningAlgorithm,
    K: JsonWebKey,
    RF: FnOnce() -> ClientAuthTokenId,
    SK: PrivateSigningKey,
> {
    issuer: String,
    subject: String,
    audience: Audience,
    duration: Duration,
    jwt_id_method: RF,
    signing_key: SK,
    signing_algo: JS,
    additional_claims: AC,
    include_nbf: bool,
    include_iat: bool,
    include_jti: bool,
    _phantom_jt: PhantomData<(AC, JE, JS, RF, K, JS)>,
}

impl<AC, JE, JS, K, RF, SK> ClientAuthTokenBuilder<AC, JE, JS, K, RF, SK>
where
    AC: AdditionalClientAuthTokenClaims,
    JE: JweContentEncryptionAlgorithm<KeyType = JS::KeyType>,
    JS: JwsSigningAlgorithm,
    K: JsonWebKey,
    RF: FnOnce() -> ClientAuthTokenId,
    SK: PrivateSigningKey,
    SK::VerificationKey: JsonWebKey<SigningAlgorithm = JS>,
{
    /// FIXME: documentation
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer: String,
        subject: String,
        audience: Audience,
        signing_key: SK,
        signing_algo: JS,
        duration: Duration,
        jwt_id_method: RF,
        additional_claims: AC,
    ) -> Self {
        Self {
            issuer,
            subject,
            audience,
            signing_key,
            signing_algo,
            duration,
            jwt_id_method,
            additional_claims,
            include_iat: false,
            include_nbf: false,
            include_jti: true,
            _phantom_jt: PhantomData,
        }
    }

    /// FIXME: documentation
    pub fn set_issuer(mut self, issuer: String) -> Self {
        self.issuer = issuer;
        self
    }

    /// FIXME: documentation
    pub fn set_subject(mut self, subject: String) -> Self {
        self.subject = subject;
        self
    }

    /// FIXME: documentation
    pub fn set_audience(mut self, audience: Audience) -> Self {
        self.audience = audience;
        self
    }

    /// FIXME: documentation
    pub fn set_signing_key(mut self, signing_key: SK) -> Self {
        self.signing_key = signing_key;
        self
    }

    /// FIXME: documentation
    pub fn set_signing_algo(mut self, signing_algo: JS) -> Self {
        self.signing_algo = signing_algo;
        self
    }

    /// FIXME: documentation
    pub fn set_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }

    /// FIXME: documentation
    pub fn set_jwt_id_method(mut self, jwt_id_method: RF) -> Self {
        self.jwt_id_method = jwt_id_method;
        self
    }

    /// FIXME: documentation
    pub fn set_additional_claims(mut self, additional_claims: AC) -> Self {
        self.additional_claims = additional_claims;
        self
    }

    /// FIXME: documentation
    pub fn include_not_before(mut self, include_nbf: bool) -> Self {
        self.include_nbf = include_nbf;
        self
    }

    /// FIXME: documentation
    pub fn include_issued_at(mut self, include_iat: bool) -> Self {
        self.include_iat = include_iat;
        self
    }

    /// FIXME: documentation
    pub fn include_jwt_id(mut self, include_jti: bool) -> Self {
        self.include_jti = include_jti;
        self
    }

    /// FIXME: documentation
    pub fn build(self) -> Result<ClientAuthToken<AC, JE, JS>, JsonWebTokenError> {
        let now = chrono::Utc::now();

        let expiration = now + self.duration;
        let not_before = if self.include_nbf { Some(now) } else { None };
        let issued_at = if self.include_iat { Some(now) } else { None };
        let jwt_id = if self.include_jti {
            let f = self.jwt_id_method;
            Some(f())
        } else {
            None
        };

        let claims = ClientAuthTokenClaims {
            issuer: self.issuer,
            subject: self.subject,
            audience: self.audience,
            expiration,
            not_before,
            issued_at,
            jwt_id,
            additional_claims: self.additional_claims,
        };

        let t = ClientAuthToken::new(claims, &self.signing_key, self.signing_algo).unwrap();
        Ok(t)
    }
}

// #[non_exhaustive]
// pub enum JwsKeyIdMethod {
//     X5t(String),
//     X509Sha256([u8; 32]),
//     KeyId(String),
//     X509Url(String),
//     X509Sha1(Vec<u8>),
// }

/// OpenID Connect ID token.
///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ClientAuthToken<
    AC: AdditionalClientAuthTokenClaims,
    JE: JweContentEncryptionAlgorithm<KeyType = JS::KeyType>,
    JS: JwsSigningAlgorithm,
>(
    #[serde(bound = "AC: AdditionalClientAuthTokenClaims")]
    JsonWebToken<JE, JS, ClientAuthTokenClaims<AC>, JsonWebTokenJsonPayloadSerde>,
);

impl<AC, JE, JS> ClientAuthToken<AC, JE, JS>
where
    AC: AdditionalClientAuthTokenClaims,
    JE: JweContentEncryptionAlgorithm<KeyType = JS::KeyType>,
    JS: JwsSigningAlgorithm,
{
    /// FIXME: documentation
    pub fn new<S>(
        claims: ClientAuthTokenClaims<AC>,
        signing_key: &S,
        alg: JS,
        // access_token: Option<&AccessToken>,
        // code: Option<&AuthorizationCode>,
    ) -> Result<Self, JsonWebTokenError>
    where
        S: PrivateSigningKey,
        S::VerificationKey: JsonWebKey<SigningAlgorithm = JS>,
    {
        JsonWebToken::new(ClientAuthTokenClaims { ..claims }, signing_key, &alg).map(Self)
    }
}

impl<AC, JE, JS> Display for ClientAuthToken<AC, JE, JS>
where
    AC: AdditionalClientAuthTokenClaims,
    JE: JweContentEncryptionAlgorithm<KeyType = JS::KeyType>,
    JS: JwsSigningAlgorithm,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let val = serde_json::to_value(self)
            // This should never arise, since we're just asking serde_json to serialize the
            // signing input concatenated with the signature, both of which are precomputed.
            .expect("ID token serialization failed");
        f.write_str(
            val.as_str()
                // This should also never arise, since our IdToken serializer always calls serialize_str
                .expect("ID token serializer did not produce a str"),
        )
    }
}

/*
#[cfg(test)]
mod tests {

    use std::time::Duration;

    use oauth2::{reqwest::http_client, AuthUrl};

    use crate::{
        core::{
            CoreAuthDisplay, CoreClaimName, CoreClaimType, CoreClientAuthMethod, CoreGrantType,
            CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse,
            CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
            CoreJwsSigningAlgorithm, CoreResponseMode, CoreRsaPrivateSigningKey,
            CoreSubjectIdentifierType,
        },
        jwt::tests::TEST_RSA_PRIV_KEY,
        AdditionalProviderMetadata, ClaimName, Client, EmptyAdditionalProviderMetadata,
        JsonWebKeyId, JsonWebKeySetUrl, ProviderMetadata, ResponseType, ResponseTypes,
    };

    use crate::core::{
        CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreResponseType,
        CoreUserInfoClaims,
    };
    use crate::{
        AccessTokenHash, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
        IssuerUrl, Nonce, PkceCodeChallenge, RedirectUrl, Scope,
    };

    use super::*;
    use anyhow::anyhow;

    #[derive(Debug, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize)]
    pub struct CoreClaimName2(String);
    impl ClaimName for CoreClaimName2 {}

    use crate::{OAuth2TokenResponse, TokenResponse};

    type MicrosoftProviderMetadata = ProviderMetadata<
        EmptyAdditionalProviderMetadata,
        CoreAuthDisplay,
        CoreClientAuthMethod,
        CoreClaimName,
        CoreClaimType,
        CoreGrantType,
        CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
        CoreJwsSigningAlgorithm,
        CoreJsonWebKeyType,
        CoreJsonWebKeyUse,
        CoreJsonWebKey,
        CoreResponseMode,
        CoreResponseType,
        CoreSubjectIdentifierType,
    >;

    #[test]
    fn azure_ad_style() -> Result<(), anyhow::Error> {
        let private_key = CoreRsaPrivateSigningKey::from_pem(
            TEST_RSA_PRIV_KEY,
            Some(JsonWebKeyId::new("flyveQx6E1p5crtxOzA64kwjYmo".to_string())),
        )
        .unwrap();
        const tenant_id: &str = "3d02d73d-a23a-4989-93ef-ac3c459edabb";

        let client_id = ClientId::new("9aca7c0e-8e4a-4b36-8c69-1c2323092699".to_string());
        let issuer = IssuerUrl::new(
            format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0",
                tenant_id
            )
            .to_string(),
        )
        .unwrap();
        let authorization_endpoint = AuthUrl::new(format!(
            "https://login.microsoft.com/{}/oauth2/v2.0/authorize",
            tenant_id
        ))
        .unwrap();

        let provider_metadata = MicrosoftProviderMetadata::discover(
            &IssuerUrl::new(format!(
                "https://login.microsoftonline.com/{}/v2.0",
                tenant_id
            ))
            .unwrap(),
            http_client,
        )
        .unwrap();

        let client = CoreClient::from_provider_metadata(provider_metadata, client_id, None);

        println!("HERE1");

        let client_auth_token_builder = client.client_auth_token_builder(
            private_key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            Duration::from_secs(30),
            || ClientAuthTokenId("haha".to_string()),
            EmptyAdditionalClientAuthTokenClaims {},
        );

        let token = client_auth_token_builder.build().unwrap();
        println!("HERE2");

        let token_response = client
            .exchange_client_credential_with_auth_token(token)
            .unwrap()
            .add_scope(Scope::new(
                "https://0fsxp-admin.sharepoint.com/.default".to_string(),
            ))
            .request(http_client)
            .unwrap();

        println!("HERE3");
        eprintln!("token_response = {:?}", token_response);

        Ok(())
    }
}
*/
