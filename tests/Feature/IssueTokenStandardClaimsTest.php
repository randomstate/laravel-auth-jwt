<?php


namespace RandomState\LaravelAuth\Tests\Feature;


use Carbon\Carbon;
use Carbon\CarbonInterval;
use RandomState\LaravelAuth\Strategies\Jwt\Issuer;
use RandomState\LaravelAuth\Tests\TestCase;

class IssueTokenStandardClaimsTest extends TestCase
{
    /**
     * @var Issuer
     */
    protected $issuer;

    protected function setUp() : void
    {
        parent::setUp();
        date_default_timezone_set('UTC');
        $this->issuer = $this->app->make(Issuer::class);
    }

    /**
     * @test
     */
    public function audience_is_set_when_supplied()
    {
        $this->issuer->withAudience('me');
        $token = $this->issuer->issue('test');

        $this->assertEquals('me', $token->getClaim('aud'));
    }


    /**
     * @test
     */
    public function issued_at_is_set_to_custom_time_when_supplied_with_datetime()
    {
        $now = now()->subDay(2)->subHours(1)->subMinutes(491);
        $this->issuer->setNow($now);
        $token = $this->issuer->issue('test');

        $this->assertEquals($now->timestamp, $token->getClaim('iat'));
    }

    /**
     * @test
     */
    public function issued_at_is_set_to_custom_time_when_supplied_with_closure_resolving_to_datetime()
    {
        $now = null;
        $this->issuer->setNow(function() use(&$now) {
            return Carbon::createFromTimestamp($now = Carbon::now()->subDay(2)->timestamp);
        });

        $token = $this->issuer->issue('test');
        $this->assertEquals($now, $token->getClaim('iat'));
    }

    /**
     * @test
     */
    public function expiration_is_set_when_supplied()
    {
        $this->issuer->withFixedExpiration($exp = Carbon::now()->addHour());
        $token = $this->issuer->issue('test');

        $this->assertEquals($exp->timestamp, $token->getClaim('exp'));
    }

    /**
     * @test
     */
    public function expiration_is_set_when_expiration_window_supplied()
    {
        $this->issuer->setNow($now = now());
        $this->issuer->withExpirationWindow($window = CarbonInterval::hours(2));
        $token = $this->issuer->issue('test');

        $this->assertEquals(now()->add($window)->timestamp, $token->getClaim('exp'));
    }

    /**
     * @test
     */
    public function fixed_expiration_overrides_window()
    {
        $this->issuer->withFixedExpiration($now = now());
        $this->issuer->withExpirationWindow($window = CarbonInterval::hours(2));
        $token = $this->issuer->issue('test');

        $this->assertEquals($now->timestamp, $token->getClaim('exp'));
    }

    /**
     * @test
     */
    public function not_before_is_set_when_supplied()
    {
        $this->issuer->withFixedNotBefore($now = now());
        $token = $this->issuer->issue('test');

        $this->assertEquals($now->timestamp, $token->getClaim('nbf'));
    }

    /**
     * @test
     */
    public function not_before_is_set_when_window_supplied()
    {
        $this->issuer->withNotBeforeWindow($window = CarbonInterval::minutes(3));
        $token = $this->issuer->issue('test');

        $this->assertEquals(now()->add($window)->timestamp, $token->getClaim('nbf'));
    }

    /**
     * @test
     */
    public function fixed_not_before_overrides_window()
    {
        $this->issuer->withFixedNotBefore(now());
        $this->issuer->withNotBeforeWindow($window = CarbonInterval::minutes(3));
        $token = $this->issuer->issue('test');

        $this->assertEquals(now()->timestamp, $token->getClaim('nbf'));
    }

    /**
     * @test
     */
    public function can_set_issuer() {
        $this->issuer->withIssuer('me');
        $token = $this->issuer->issue('test');

        $this->assertEquals('me', $token->getClaim('iss'));
    }
}