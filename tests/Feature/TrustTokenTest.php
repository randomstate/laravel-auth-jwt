<?php


namespace RandomState\LaravelAuth\Tests\Feature;


use Lcobucci\JWT\Signer\Hmac\Sha256;
use RandomState\LaravelAuth\Strategies\Jwt\Issuer;
use RandomState\LaravelAuth\Tests\TestCase;

class TrustTokenTest extends TestCase
{
    /**
     * @var Issuer
     */
    protected $issuer;

    protected function setUp()
    {
        parent::setUp();
        $this->issuer = $this->app->make(Issuer::class);
    }

    /**
     * @test
     */
    public function can_verify_tokens_signed_using_a_signing_algorithm()
    {
        $unsigned = $this->issuer->issue('unsigned');
        $unsignedVerification = $this->issuer->verify($unsigned);

        $this->issuer->signTokens(new Sha256, 'this_is_a_test');
        $token = $this->issuer->issue('test');

        $this->assertTrue($unsignedVerification);
        $this->assertTrue($this->issuer->verify($token));

        $this->issuer->signTokens(new Sha256, 'changed_key');
        $this->assertFalse($this->issuer->verify($token));
    }
}