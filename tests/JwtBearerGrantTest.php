<?php

namespace Tests;

use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use MilesChou\OAuth2\JwtBearerGrant;
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
    public function shouldBeOkayWithEs256()
    {
        $this->target->setKeyFile('file://' . __DIR__ . '/Stubs/es256-private.key');
        $jws = $this->createAssertion('file://' . __DIR__ . '/Stubs/es256-private.key', 'ES256');

        $_POST['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
        $_POST['assertion'] = (new CompactSerializer(new StandardConverter()))->serialize($jws);

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

    /**
     * @test
     */
    public function shouldBeOkayWithRs256()
    {
        $this->target->setKeyFile('file://' . __DIR__ . '/Stubs/private.key');
        $jws = $this->createAssertion('file://' . __DIR__ . '/Stubs/private.key', 'RS256');

        $_POST['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
        $_POST['assertion'] = (new CompactSerializer(new StandardConverter()))->serialize($jws);

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

    /**
     * @test
     */
    public function shouldThrowExceptionWhenBadAudience()
    {
        $this->expectException(InvalidClaimException::class);

        $this->target->setOption('audience', 'who are you');
        $this->target->setKeyFile('file://' . __DIR__ . '/Stubs/private.key');
        $jws = $this->createAssertion('file://' . __DIR__ . '/Stubs/private.key', 'RS256');

        $_POST['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
        $_POST['assertion'] = (new CompactSerializer(new StandardConverter()))->serialize($jws);

        $responseType = new BearerTokenResponse();
        $responseType->setPrivateKey(new CryptKey('file://' . __DIR__ . '/Stubs/private.key'));

        // Act
        $this->target->respondToAccessTokenRequest(
            ServerRequestFactory::fromGlobals(),
            $responseType,
            new \DateInterval('PT1H')
        );
    }

    /**
     * @test
     */
    public function shouldBeOkayWhenAudienceOk()
    {
        $this->target->setKeyFile('file://' . __DIR__ . '/Stubs/private.key');
        $jws = $this->createAssertion('file://' . __DIR__ . '/Stubs/private.key', 'RS256');

        // Set the audience
        $this->target->setOption('audience', json_decode($jws->getPayload(), true)['aud']);

        $_POST['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
        $_POST['assertion'] = (new CompactSerializer(new StandardConverter()))->serialize($jws);

        $responseType = new BearerTokenResponse();
        $responseType->setPrivateKey(new CryptKey('file://' . __DIR__ . '/Stubs/private.key'));

        // Act
        $responseType = $this->target->respondToAccessTokenRequest(
            ServerRequestFactory::fromGlobals(),
            $responseType,
            new \DateInterval('PT1H')
        );

        $this->assertInstanceOf(ResponseTypeInterface::class, $responseType);
    }
}
