<?php


namespace RandomState\LaravelAuth\Strategies\Jwt;


use Lcobucci\JWT\Signer;

class Issuer
{
    /**
     * @var Signer
     */
    protected $signer = null;
    protected $key = null;

    public function __construct()
    {

    }

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

//    public function issueOnce($id, $subject, $audience = null, $expiration = null, $issuedAt = null, $issuer = null, $notBefore = null)
//    {
//        return $this->build($id, $subject, $audience, $expiration, $issuedAt, $issuer, $notBefore)->getToken();
//    }
//
//    protected function build($id, $subject, $audience = null, $expiration = null, $issuedAt = null, $issuer = null, $notBefore = null)
//    {
//        $builder = new Builder();
//        $builder
//            ->setId($id)
//            ->setSubject($subject);
//
//
//
////        $builder->sign($this->signer, $this->key);
//
//        return $builder;
//    }

    protected function builder()
    {
        return new Builder;
    }
}