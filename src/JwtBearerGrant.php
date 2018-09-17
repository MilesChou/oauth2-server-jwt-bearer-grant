<?php

namespace MilesChou\OAuth2;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
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
    /**
     * @var AlgorithmManager
     */
    private $algorithmManager;

    /**
     * @var string|null
     */
    private $keyFile;

    /**
     * @param string|null $keyFile
     */
    public function __construct($keyFile = null)
    {
        $this->setKeyFile($keyFile);
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
        $jws = $this->validateAssertion($request);
        $scopes = $this->validateScopes($this->getRequestParameter('scope', $request, $this->defaultScope));

        $client = $this->clientRepository->getClientEntity(
            $jws['iss'],
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

    /**
     * @return AlgorithmManager
     */
    public function getAlgorithmManager(): AlgorithmManager
    {
        if (null === $this->algorithmManager) {
            $this->algorithmManager = AlgorithmManager::create([
                new RS256(),
                new HS256(),
                new ES256(),
            ]);
        }

        return $this->algorithmManager;
    }

    /**
     * {@inheritdoc}
     */
    public function getIdentifier()
    {
        return 'urn:ietf:params:oauth:grant-type:jwt-bearer';
    }

    /**
     * @param AlgorithmManager $algorithmManager
     * @return static
     */
    public function setAlgorithmManager(AlgorithmManager $algorithmManager): JwtBearerGrant
    {
        $this->algorithmManager = $algorithmManager;

        return $this;
    }

    /**
     * @param string $keyFile
     */
    public function setKeyFile($keyFile)
    {
        $this->keyFile = $keyFile;
    }

    protected function validateAssertion(ServerRequestInterface $request)
    {
        // If the client is confidential require the client secret
        $assertion = $this->getRequestParameter('assertion', $request);

        if (null === $assertion) {
            throw OAuthServerException::invalidRequest('assertion');
        }

        $jws = $this->resolveJwsSerializerManager()->unserialize($assertion);
        $jwk = JWKFactory::createFromKeyFile($this->keyFile);

        if (!$this->resolveJwsVerifier()->verifyWithKey($jws, $jwk, 0)) {
            throw new \Exception('wtf');
        }

        return json_decode($jws->getPayload(), true);
    }

    protected function resolveJwsVerifier(): JWSVerifier
    {
        return new JWSVerifier($this->getAlgorithmManager());
    }

    protected function resolveJwsSerializerManager(): JWSSerializerManager
    {
        return JWSSerializerManager::create([
            new CompactSerializer(new StandardConverter()),
        ]);
    }
}
