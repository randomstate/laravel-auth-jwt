<?php


namespace RandomState\LaravelAuth\Strategies\Jwt;


use DateInterval;
use DateTime;
use Lcobucci\JWT\Signer;

class Builder
{
    use JwtBuilder;

    /**
     * @var \Lcobucci\JWT\Builder
     */
    protected $builder;

    /**
     * @var DateTime | null
     */
    protected $issuedAt;

    /**
     * @var string | null
     */
    protected $issuer;

    /**
     * @var array
     */
    protected $claims = [];

    /**
     * @var string
     */
    protected $id;

    /**
     * @var string
     */
    protected $subject;

    /**
     * @var Signer | null
     */
    protected $signer = null;

    /**
     * @var
     */
    protected $key = null;

    public function __construct()
    {
        $this->builder = new \Lcobucci\JWT\Builder();
    }

    public function getToken()
    {
        $this->builder
            ->setId($this->id)
            ->setSubject($this->subject);

        foreach ($this->claims as $key => $value) {
            $this->builder->set($key, $value);
        }

        $this->builder
            ->setIssuedAt($this->now()->getTimestamp())
            ->setExpiration($this->expiration()->getTimestamp());

        if ($this->audience) {
            $this->builder->setAudience($this->audience);
        }

        if ($this->notBefore()) {
            $this->builder->setNotBefore($this->notBefore()->getTimestamp());
        }

        if ($this->signer && $this->key) {
            $this->builder->sign($this->signer, $this->key);
        }

        return $this->builder->getToken();
    }

    public function withClaims(array $claims = [])
    {
        $this->claims = $claims;

        return $this;
    }

    public function withId($id)
    {
        $this->id = $id;

        return $this;
    }

    public function signWith(Signer $signer = null, $key = null)
    {
        $this->signer = $signer;
        $this->key = $key;

        return $this;
    }

    public function withSubject($subject)
    {
        $this->subject = $subject;

        return $this;
    }

    /**
     * @return DateTime
     */
    protected function now()
    {
        if ($this->now instanceof \Closure) {
            return clone ($this->now)();
        }

        return $this->now ? clone $this->now : new DateTime;
    }

    protected function expiration()
    {
        if ($this->expiration) {
            return $this->expiration;
        }

        return $this->now()->add($this->expirationWindow());
    }

    protected function expirationWindow()
    {
        return $this->expirationWindow ? $this->expirationWindow : new DateInterval('PT1H');
    }

    public function withAudience($audience)
    {
        $this->audience = $audience;

        return $this;
    }

    protected function notBefore()
    {
        if ($this->notBefore) {
            return $this->notBefore;
        }

        return $this->notBeforeWindow ? $this->now()->add($this->notBeforeWindow) : null;
    }
}