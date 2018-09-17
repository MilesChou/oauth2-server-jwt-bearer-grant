<?php

namespace Tests;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;

class TestCase extends \PHPUnit\Framework\TestCase
{
    protected function createAssertion($keyFile, $alg): JWS
    {
        // The algorithm manager with the HS256 algorithm.
        $algorithmManager = AlgorithmManager::create([
            new HS256(),
            new RS256(),
            new ES256(),
        ]);

        $jwk = JWKFactory::createFromKeyFile($keyFile);

        $jsonConverter = new StandardConverter();

        $jwsBuilder = new JWSBuilder(
            $jsonConverter,
            $algorithmManager
        );

        $payload = $jsonConverter->encode([
            'iat' => time(),
            'nbf' => time(),
            'exp' => time() + 3600,
            'iss' => 'My service',
            'aud' => 'Your app',
        ]);

        return $jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature($jwk, ['alg' => $alg])
            ->build();
    }
}
