<?php


namespace RandomState\LaravelAuth\Strategies\Jwt;


use DateInterval;
use DateTime;

trait JwtBuilder
{
    /**
     * @var string
     */
    protected $audience;

    /**
     * @var \DateTime | null | \Closure
     */
    protected $now = null;

    /**
     * @var DateTime | null
     */
    protected $expiration = null;

    /**
     * @var DateInterval | null
     */
    protected $expirationWindow = null;

    /**
     * @var DateTime | null
     */
    protected $notBefore = null;

    /**
     * @var DateInterval | null
     */
    protected $notBeforeWindow = null;

    public function withAudience($audience)
    {
        $this->audience = $audience;

        return $this;
    }

    public function setNow($now = null)
    {
        $this->now = $now;

        return $this;
    }

    public function withFixedExpiration(DateTime $expiration = null)
    {
        $this->expiration = $expiration;

        return $this;
    }

    public function withExpirationWindow(DateInterval $expirationWindow = null)
    {
        $this->expirationWindow = $expirationWindow;

        return $this;
    }

    public function withFixedNotBefore(DateTime $notBefore = null)
    {
        $this->notBefore = $notBefore;

        return $this;
    }

    public function withNotBeforeWindow(DateInterval $notBeforeWindow = null)
    {
        $this->notBeforeWindow = $notBeforeWindow;

        return $this;
    }
}