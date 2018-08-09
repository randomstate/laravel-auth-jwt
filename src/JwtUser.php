<?php


namespace RandomState\LaravelAuth\Strategies;


use Lcobucci\JWT\Token;

class JwtUser
{
    protected $id;

    /**
     * @var array
     */
    protected $claims;

    /**
     * @var Token
     */
    protected $token;

    public function __construct($id, Token $token)
    {
        $this->id = $id;
        $this->token = $token;
    }

    public function id()
    {
        return $this->id;
    }

    public function token()
    {
        return $this->token;
    }
}