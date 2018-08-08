<?php


namespace RandomState\LaravelAuth\Strategies\Jwt;


use DateInterval;
use DateTime;
use Lcobucci\JWT\Signer;

class Builder
{
    /**
     * @var \Lcobucci\JWT\Builder
     */
    protected $builder;

    /**
     * @var string | null
     */
    protected $audience;

    /**
     * @var DateTime | null
     */
    protected $expiration;

    /**
     * @var DateInterval | null
     */
    protected $expirationWindow;

    /**
     * @var DateTime | null
     */
    protected $issuedAt;

    /**
     * @var boolean
     */
    protected $hideIssuedAt = false;

    /**
     * @var string | null
     */
    protected $issuer;

    /**
     * @var DateTime | null
     */
    protected $notBefore;

    /**
     * @var DateInterval | null
     */
    protected $notBeforeWindow;

    /**
     * @var DateTime
     */
    protected $now;

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
}