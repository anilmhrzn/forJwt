<?php
// src/EventListener/JWTListener.php
namespace App\EventListener;

use App\Service\JWTService;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

class JWTListener
{
private $jwtService;

public function __construct(JWTService $jwtService)
{
$this->jwtService = $jwtService;
}

public function onKernelRequest(RequestEvent $event)
{
$request = $event->getRequest();

// Exclude some routes from token verification
if (preg_match('/^\/api\/login/', $request->getPathInfo())) {
return;
}

$token = $request->headers->get('Authorization');

if (!$token || !$this->isTokenValid($token)) {
throw new AccessDeniedHttpException('Invalid or missing JWT token');
}
}

private function isTokenValid(string $token): bool
{
$token = str_replace('Bearer ', '', $token);
return $this->jwtService->validateToken($token) !== null;
}
}
