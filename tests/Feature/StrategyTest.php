<?php


namespace RandomState\LaravelAuth\Tests\Feature;


use RandomState\LaravelAuth\Tests\TestCase;

class StrategyTest extends TestCase
{

    /**
     * @test
     */
    public function can_authenticate_a_user_using_a_token()
    {
        $token = $this->issuer->issue($subject = 'user_12345', $claims = [
            'permissions' => [
                'can.do.anything',
            ],
            'birthday' => '2018-01-01',
        ]);

        $user = $this->strategy->attempt($token);

        $this->assertEquals($subject, $user->getId());
        $this->assertEquals($claims, $user->getClaims());
    }
}