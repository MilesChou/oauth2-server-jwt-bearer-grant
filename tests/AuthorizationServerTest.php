<?php

namespace Tests;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use MilesChou\OAuth2\JwtBearerGrant;
use Tests\Stubs\AccessTokenEntity;
use Tests\Stubs\ClientEntity;
use Tests\Stubs\ScopeEntity;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequestFactory;

class AuthorizationServerTest extends TestCase
{
    public function setUp()
    {
        // Make sure the keys have the correct permissions.
        chmod(__DIR__ . '/Stubs/private.key', 0600);
        chmod(__DIR__ . '/Stubs/public.key', 0600);
    }

    public function testValidateJwtBearerGrant()
    {
        $clientEntity = new ClientEntity();
        $clientRepository = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepository->method('getClientEntity')->willReturn($clientEntity);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);


        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());

        $server = new AuthorizationServer(
            $clientRepository,
            $accessTokenRepositoryMock,
            $scopeRepositoryMock,
            'file://' . __DIR__ . '/Stubs/private.key',
            'file://' . __DIR__ . '/Stubs/public.key'
        );

        $server->enableGrantType(new JwtBearerGrant('file://' . __DIR__ . '/Stubs/public.key'));

        $_POST['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
        $_POST['assertion'] = $this->createAssertion();

        $response = $server->respondToAccessTokenRequest(ServerRequestFactory::fromGlobals(), new Response);

        $json = json_decode($response->getBody(), true);
        $jwt = (new Parser)->parse($json['access_token']);

        $this->assertInstanceOf(Token::class, $jwt);
    }

    public function testValidateJwtBearerGrantUsingAnotherAlg()
    {
        $clientEntity = new ClientEntity();
        $clientRepository = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepository->method('getClientEntity')->willReturn($clientEntity);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);


        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());

        $server = new AuthorizationServer(
            $clientRepository,
            $accessTokenRepositoryMock,
            $scopeRepositoryMock,
            'file://' . __DIR__ . '/Stubs/private.key',
            'file://' . __DIR__ . '/Stubs/public.key'
        );

        $server->enableGrantType(new JwtBearerGrant('file://' . __DIR__ . '/Stubs/es256-public.key'));

        $_POST['grant_type'] = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
        $_POST['assertion'] = $this->createAssertion();

        $this->markTestIncomplete();

        $response = $server->respondToAccessTokenRequest(ServerRequestFactory::fromGlobals(), new Response);


        $json = json_decode($response->getBody(), true);
        $jwt = (new Parser)->parse($json['access_token']);

        $this->assertInstanceOf(Token::class, $jwt);
    }
}
