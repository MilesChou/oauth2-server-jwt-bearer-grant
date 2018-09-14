<?php

namespace Tests;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Token;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use MilesChou\OAuth2\JwtBearerGrant;
use PHPUnit\Framework\TestCase;
use Tests\Stubs\AccessTokenEntity;
use Tests\Stubs\ClientEntity;
use Tests\Stubs\ScopeEntity;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequestFactory;

class JwtBearerGrantTest extends TestCase
{
    /**
     * @var JwtBearerGrant
     */
    private $target;

    public function setUp()
    {
        $this->target = new JwtBearerGrant();

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn(new ClientEntity());

        $this->target->setClientRepository($clientRepositoryMock);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn(new ScopeEntity());
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $this->target->setScopeRepository($scopeRepositoryMock);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());

        $this->target->setAccessTokenRepository($accessTokenRepositoryMock);

        // Make sure the keys have the correct permissions.
        chmod(__DIR__ . '/Stubs/private.key', 0600);
        chmod(__DIR__ . '/Stubs/public.key', 0600);
        chmod(__DIR__ . '/Stubs/es256-private.key', 0600);
        chmod(__DIR__ . '/Stubs/es256-public.key', 0600);
    }

    public function tearDown()
    {
        $this->target = null;
    }

    /**
     * @test
     */
    public function shouldBeOkay()
    {
        $this->target->setPublicKey('file://' . __DIR__ . '/Stubs/public.key');

        $_POST['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
        $_POST['assertion'] = (string)(new Builder)
            ->setIssuer('http://example.com')
            ->setAudience('http://example.org')
            ->setId('4f1g23a12aa')
            ->setIssuedAt(time())
            ->setNotBefore(time() + 60)
            ->setExpiration(time() + 3600)
            ->set('uid', 1)
            ->sign(new Rsa\Sha256(), file_get_contents(__DIR__ . '/Stubs/private.key'))
            ->getToken();

        $responseType = new BearerTokenResponse();
        $responseType->setPrivateKey(new CryptKey('file://' . __DIR__ . '/Stubs/private.key'));

        $responseType = $this->target->respondToAccessTokenRequest(
            ServerRequestFactory::fromGlobals(),
            $responseType,
            new \DateInterval('PT1H')
        );

        $response = $responseType->generateHttpResponse(new Response());

        $json = json_decode($response->getBody(), true);
        $jwt = (new Parser)->parse($json['access_token']);

        $this->assertInstanceOf(Token::class, $jwt);
        $this->assertSame('RS256', $jwt->getHeader('alg'));
    }
}
