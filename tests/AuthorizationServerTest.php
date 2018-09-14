<?php

namespace Tests;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use MilesChou\OAuth2\JwtBearerGrant;
use PHPUnit\Framework\TestCase;
use Tests\Stubs\AccessTokenEntity;
use Tests\Stubs\ClientEntity;
use Tests\Stubs\ScopeEntity;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequestFactory;

class AuthorizationServerTest extends TestCase
{
    const DEFAULT_SCOPE = 'basic';

    public function setUp()
    {
        // Make sure the keys have the correct permissions.
        chmod(__DIR__ . '/Stubs/private.key', 0600);
        chmod(__DIR__ . '/Stubs/public.key', 0600);
        chmod(__DIR__ . '/Stubs/private.key.crlf', 0600);
    }

    public function testValidateJwtBearerGrant()
    {
        $clientEntity = new ClientEntity();
        $clientRepository = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepository->method('getClientEntity')->willReturn($clientEntity);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());

        $grant = new JwtBearerGrant('file://' . __DIR__ . '/Stubs/public.key');
        $grant->setClientRepository($clientRepository);

        $server = new AuthorizationServer(
            $clientRepository,
            $accessTokenRepositoryMock,
            $scopeRepositoryMock,
            'file://' . __DIR__ . '/Stubs/private.key',
            'file://' . __DIR__ . '/Stubs/public.key'
        );
        $server->enableGrantType($grant);

        $_POST['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
        $_POST['assertion'] = (string)(new Builder)
            ->setIssuer('http://example.com')
            ->setAudience('http://example.org')
            ->setId('4f1g23a12aa')
            ->setIssuedAt(time())
            ->setNotBefore(time() + 60)
            ->setExpiration(time() + 3600)
            ->set('uid', 1)
            ->sign(new Sha256(), file_get_contents(__DIR__ . '/Stubs/private.key'))
            ->getToken();

        $response = $server->respondToAccessTokenRequest(ServerRequestFactory::fromGlobals(), new Response);


        $json = json_decode($response->getBody(), true);
        $jwt = (new Parser)->parse($json['access_token']);

        $this->assertInstanceOf(Token::class, $jwt);

    }
}