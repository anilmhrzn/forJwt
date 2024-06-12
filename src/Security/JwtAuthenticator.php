<?php
namespace App\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\BadgeInterface;

class JwtAuthenticator extends AbstractAuthenticator {
    private $secret;

    public function __construct($secret) {
        $this->secret = $secret;
    }

    public function supports(Request $request): ?bool {
        return $request->headers->has('Authorization');
    }

    public function authenticate(Request $request): SelfValidatingPassport
    {
        $authHeader = $request->headers->get('Authorization');

        if (null === $authHeader || 0 !== strpos($authHeader, 'Bearer ')) {
            throw new CustomUserMessageAuthenticationException('No JWT token found');
        }

        $jwt = substr($authHeader, 7);
        return new SelfValidatingPassport(new UserBadge($jwt, function($jwt) {
            return $this->getUserFromJwt($jwt);
        }));
    }

    private function getUserFromJwt($jwt) {
        $parts = explode('.', $jwt);

        if (count($parts) !== 3) {
            throw new CustomUserMessageAuthenticationException('Invalid JWT');
        }

        [$header, $payload, $signature] = $parts;
        $payload = json_decode(base64_decode($payload), true);

        if ($payload['exp'] < time()) {
            throw new CustomUserMessageAuthenticationException('JWT token has expired');
        }

        $expectedSignature = $this->base64UrlEncode(hash_hmac('sha256', "$header.$payload", $this->secret, true));

        if (!hash_equals($expectedSignature, $signature)) {
            throw new CustomUserMessageAuthenticationException('Invalid JWT signature');
        }

        // Simply return the user data as an associative array
        return $payload;
    }

    public function onAuthenticationSuccess(Request $request, $token, string $firewallName): ?JsonResponse {
        // Returning null means continue the request
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?JsonResponse {
        return new JsonResponse(['error' => 'Authentication failed'], JsonResponse::HTTP_UNAUTHORIZED);
    }

//    private function base64UrlEncode(string $hash_hmac)
//    {
//    }
    private function base64UrlEncode(String $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
