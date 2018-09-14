<?php

namespace MilesChou\OAuth2;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * JWT bearer grant class.
 */
class JwtBearerGrant extends AbstractGrant
{
    private $publicKey;

    public function __construct($publicKey)
    {
        $this->publicKey = $publicKey;
    }

    /**
     * {@inheritdoc}
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        \DateInterval $accessTokenTTL
    ) {
        // Validate request
        $jwt = $this->validateAssertion($request);
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request, $this->defaultScope));

        $client = $this->clientRepository->getClientEntity(
            $jwt->getClaim('iss'),
            $this->getIdentifier()
        );

        // Finalize the requested scopes
        $finalizedScopes = $this->scopeRepository->finalizeScopes($scopes, $this->getIdentifier(), $client);

        // Issue and persist access token
        $accessToken = $this->issueAccessToken($accessTokenTTL, $client, null, $finalizedScopes);

        // Send event to emitter
        $this->getEmitter()->emit(new RequestEvent('access_token.issued', $request));

        // Inject access token into response type
        $responseType->setAccessToken($accessToken);

        return $responseType;
    }

    protected function validateAssertion(ServerRequestInterface $request)
    {
        // If the client is confidential require the client secret
        $assertion = $this->getRequestParameter('assertion', $request);

        if (null === $assertion) {
            throw OAuthServerException::invalidRequest('assertion');
        }

        $jwt = (new Parser)->parse($assertion);
        $jwt->verify(new Sha256(), $this->publicKey);

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier()
    {
        return 'urn:ietf:params:oauth:grant-type:jwt-bearer';
    }
}
