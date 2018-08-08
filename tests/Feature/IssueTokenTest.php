<?php


namespace RandomState\LaravelAuth\Tests\Feature;


use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Token;
use RandomState\LaravelAuth\Strategies\Jwt\Issuer;
use RandomState\LaravelAuth\Tests\TestCase;

class IssueTokenTest extends TestCase
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
    public function can_generate_a_jwt_token()
    {
        /** @var Token $token */
        $token = $this->issuer->issue('user');

        $this->assertInstanceOf(Token::class, $token);
        $this->assertEquals('user', $token->getClaim('sub'));
    }

    /**
     * @test
     */
    public function can_generate_a_jwt_token_with_custom_claims()
    {
        /** @var Token $token */
        $token = $this->issuer->issue('user', [
            'nickname' => 'Johnny',
            'hair_colour' => 'Brown',
        ]);

        $this->assertEquals('Johnny', $token->getClaim('nickname'));
        $this->assertEquals('Brown', $token->getClaim('hair_colour'));
    }

    /**
     * @test
     */
    public function can_sign_token_using_signing_implementation()
    {
        $this->issuer->signTokens(new Sha256, 'testing');
        $token = $this->issuer->issue('test');

        $jwt = $token->__toString();

        $parsedToken = (new Parser())->parse($jwt);
        $this->assertTrue($parsedToken->verify(new Sha256, 'testing'));
    }


}