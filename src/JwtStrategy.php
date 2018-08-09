<?php


namespace RandomState\LaravelAuth\Strategies;


use Illuminate\Http\Request;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;
use RandomState\LaravelAuth\AbstractAuthStrategy;
use RandomState\LaravelAuth\Strategies\Jwt\Issuer;

class JwtStrategy extends AbstractAuthStrategy
{
    /**
     * @var Issuer
     */
    protected $issuer;

    public function __construct(Issuer $issuer)
    {
        $this->issuer = $issuer;
    }

    public function attempt(Request $request)
    {
        $token = $this->getToken($request);

        if (!$token) {
            return null;
        }

        $isValid = $this->validateToken($token);
        $isVerified = $this->verifyToken($token);

        if (!($isValid && $isVerified)) {
            return null;
        };

        return $this->tokenToUser($token);
    }

    public function getToken(Request $request)
    {
        if ($bearerToken = $request->header('Authorization')) {
            $tokenString = str_replace("Bearer ", "", $bearerToken);
        }

        $tokenString = $tokenString ?? $request->get('token');

        return $tokenString ? (new Parser)->parse($tokenString) : null;
    }

    public function validateToken(Token $token)
    {
        return $this->issuer->validate($token);
    }

    public function verifyToken(Token $token)
    {
        return $this->issuer->verify($token);
    }

    protected function tokenToUser(Token $token)
    {
        return new JwtUser($token->getClaim('sub'), $token);
    }
}