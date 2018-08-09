<?php


namespace RandomState\LaravelAuth\Strategies\Jwt;


use DateTime;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;

class Issuer
{
    use JwtBuilder;

    /**
     * @var Signer | null
     */
    protected $signer = null;

    /**
     * @var Signer\Key | string | null
     */
    protected $key = null;

    /**
     * @var string | null
     */
    protected $audience;

    public function signTokens(Signer $signer, $key)
    {
        $this->signer = $signer;
        $this->key = $key;
    }

    public function withoutSigning()
    {
        $this->signer = null;
        $this->key = null;
    }

    public function issue($subject, array $claims = [])
    {
        return $this
            ->builder()
            ->withId($subject)
            ->withIssuer($this->issuer)
            ->withSubject($subject)
            ->withClaims($claims)
            ->withAudience($this->audience)
            ->withFixedExpiration($this->expiration)
            ->withExpirationWindow($this->expirationWindow)
            ->withFixedNotBefore($this->notBefore)
            ->withNotBeforeWindow($this->notBeforeWindow)
            ->signWith($this->signer, $this->key)
            ->setNow($this->now)
            ->getToken();
    }

    protected function builder()
    {
        return new Builder;
    }

    public function validate(Token $token)
    {
        $validator = new ValidationData();

        if ($this->audience) {
            $validator->setAudience($this->audience);
        }

        $validator->setCurrentTime($this->now ? $this->now->getTimestamp() : (new DateTime())->getTimestamp());
        $validator->setSubject($token->getClaim('sub'));

        return $token->validate($validator);
    }

    public function verify(Token $token)
    {
        if (is_null($this->signer) && is_null($this->key) && $token->getHeader('alg') === 'none') {
            return true;
        }

        return $token->verify($this->signer, $this->key);
    }
}