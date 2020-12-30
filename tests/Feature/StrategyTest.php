<?php


namespace RandomState\LaravelAuth\Tests\Feature;


use Illuminate\Foundation\Testing\Concerns\MakesHttpRequests;
use Illuminate\Http\Request;
use RandomState\LaravelAuth\LaravelAuthServiceProvider;
use RandomState\LaravelAuth\Strategies\Jwt\Issuer;
use RandomState\LaravelAuth\Strategies\JwtStrategy;
use RandomState\LaravelAuth\Tests\TestCase;

class StrategyTest extends TestCase
{
    use MakesHttpRequests;

    /**
     * @var Issuer
     */
    protected $issuer;

    /**
     * @var JwtStrategy
     */
    protected $strategy;

    public function setUp() : void
    {
        parent::setUp();
        $this->issuer = $this->app->make(Issuer::class);
        $this->strategy = $this->app->make(JwtStrategy::class);

        $this->app->register(LaravelAuthServiceProvider::class);
    }

    /**
     * @test
     */
    public function can_authenticate_a_user_using_a_token()
    {
        $this->withoutExceptionHandling();
        $token = $this->issuer->issue($subject = 'user_12345', $claims = [
            'permissions' => [
                'can.do.anything',
            ],
            'birthday' => '2018-01-01',
        ]);

        $request = Request::create('test', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $token,
        ]);

        $user = $this->strategy->attempt($request);

        $this->assertEquals($subject, $user->id());
        $this->assertEquals(['can.do.anything'], (array) $user->token()->getClaim('permissions'));
        $this->assertEquals('2018-01-01', $user->token()->getClaim('birthday'));
    }
}