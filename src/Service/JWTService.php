<?php
// src/Service/JWTService.php
namespace App\Service;

class JWTService
{
private $secretKey;

public function __construct($secretKey)
{
$this->secretKey = $secretKey;
}

public function base64UrlEncode($data): string
{
return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

public function base64UrlDecode($data)
{
return base64_decode(strtr($data, '-_', '+/'));
}

public function createToken(array $payload): string
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
