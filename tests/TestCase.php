<?php

namespace Tests;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Rsa;

class TestCase extends \PHPUnit\Framework\TestCase
{
    /**
     * @return string
     */
    protected function createAssertion()
    {
        return (string)(new Builder)
            ->setIssuer('http://example.com')
            ->setAudience('http://example.org')
            ->setId('4f1g23a12aa')
            ->setIssuedAt(time())
            ->setNotBefore(time() + 60)
            ->setExpiration(time() + 3600)
            ->set('uid', 1)
            ->sign(new Rsa\Sha256(), file_get_contents(__DIR__ . '/Stubs/private.key'))
            ->getToken();
    }
}
