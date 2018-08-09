<?php


namespace RandomState\LaravelAuth\Strategies\Jwt;


use DateTime;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;

class Issuer
{
    /**
     * @var Signer | null
     */
    protected $signer = null;

    /**
     * @var Signer\Key | string | null
     */
    protected $key = null;

    /**
     * @var DateTime | null
     */
    protected $now = null;

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
            ->withSubject($subject)
            ->withClaims($claims)
            ->signWith($this->signer, $this->key)
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