<?php
namespace App\Security;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;

class ApiKeyAuthenticator extends AbstractAuthenticator

{

    public function supports(Request $request): ?bool
    {
        // TODO: Implement supports() method.
    }

    public function authenticate(Request $request): Passport
    {
        // TODO: Implement authenticate() method.
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        // TODO: Implement onAuthenticationSuccess() method.
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        // TODO: Implement onAuthenticationFailure() method.
    }



    public function base64UrlEncode($data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public function base64UrlDecode($data)
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {

    }
    public function createTheToken(array $payload): string
    {
        $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
        $header = $this->base64UrlEncode($header);

        $payload = json_encode($payload);
        $payload = $this->base64UrlEncode($payload);

        $signature = hash_hmac('sha256', "$header.$payload", $this->secretKey, true);
        $signature = $this->base64UrlEncode($signature);

        return "$header.$payload.$signature";
    }

    public function validateToken(string $token): ?array
    {
        list($header, $payload, $signature) = explode('.', $token);

        $validSignature = hash_hmac('sha256', "$header.$payload", $this->secretKey, true);
        $validSignature = $this->base64UrlEncode($validSignature);

        if ($signature !== $validSignature) {
            return null;
        }

        $payload = json_decode($this->base64UrlDecode($payload), true);

        if ($payload['exp'] < time()) {
            return null;
        }

        return $payload;
    }
}