<?php


namespace RandomState\LaravelAuth\Tests\Feature;


use RandomState\LaravelAuth\Tests\TestCase;

class TrustTokenTest extends TestCase
{
    /**
     * @test
     */
    public function can_verify_tokens_signed_using_a_signing_algorithm()
    {
        // verify that the strategy itself checks with the correct (mocked) signing algorithm
    }
}