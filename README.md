# randomstate/laravel-auth-jwt

This is a JWT authentication strategy for `randomstate/laravel-auth`.
It serves both the issuing and the authentication of JWTs.

## Usage

Register with Auth Manager: Follow strategy service provider example here: https://github.com/randomstate/laravel-auth

### Configuration

You should configure your token issuer (Issuer::class) so that the appropriate standard claims are made (iat, aud etc) depending on your needs.

```php
<?php

use \RandomState\LaravelAuth\Strategies\JwtStrategy;
use \RandomState\LaravelAuth\Strategies\Jwt\Issuer;
use \Carbon\CarbonInterval;

class MyServiceProvider extends \Illuminate\Support\ServiceProvider {
    
    public function register() {
        $this->app->resolving(\Illuminate\Auth\AuthManager::class, function($manager) {
           $manager->register('jwt', $this->app->make(JwtStrategy::class));
        });
        
        $this->app->resolving(JwtStrategy::class, function($strategy) {
           $strategy->convertUsing(function(\RandomState\LaravelAuth\Strategies\JwtUser $user) {
              return User::find($user->id()); // assuming you are using Eloquent 
           });
        });
        
        $this->app->bind(Issuer::class, function() {
            $issuer = new Issuer();
            
            $issuer
                ->withIssuer('my_app') // chain and build your configuration
                ->withAudience('my_app')
                ->withExpirationWindow(CarbonInterval::minutes(60))
                ->signTokens(new \Lcobucci\JWT\Signer\Rsa\Sha256(), config('auth.jwt_signing_key')) // your private RSA key in this example
                ;
        });
    }
}
```

### Issuing a Token
This package automatically resolves your Issuer::class configuration out of the Laravel container.
This means that any tokens issued can be checked without worrying if you have configured everything correctly - as long as
you don't change the way laravel binds the Issuer::class between issuing a token and consuming it, you can rely on it being consistent.

Typically you will want to use a specific login route to authenticate a user via username and password.
You should simply perform any login logic (usually handled out of the box with Laravel) and then issue and return a JWT token as so:

```php
<?php

use \Illuminate\Http\Request;
use \App\Http\Controllers\Controller;
use \RandomState\LaravelAuth\Strategies\Jwt\Issuer;
use \Illuminate\Support\Facades\Auth;

class LoginController extends Controller {
    
    public function login(Request $request, Issuer $issuer) {
        $token = $issuer->issue(Auth::user()->getAuthIdentifier());
        
        return response($token);
    }
}
```

### Authenticating via JWT

You may supply your JWT token as an `Authorization: Bearer {token}` header or as a `token` request parameter in your request.
This will automatically be pulled out when using the LaravelAuth authenticate middleware and authenticated.
