<?php
// src/Controller/AuthController.php
namespace App\Controller;

use App\Service\JWTService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use App\Entity\User;

class AuthController extends AbstractController
{
    private $jwtService;
    private $entityManager;

    public function __construct(JWTService $jwtService, EntityManagerInterface $entityManager)
    {
        $this->jwtService = $jwtService;
        $this->entityManager = $entityManager;
    }

    #[Route('/api/login', name: 'api_login', methods: ['POST'])]
    public function login(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        $username = $request->request->get('username') ;
        $password = $request->request->get('password');
//        return new JsonResponse(['username' =>$username,"password",$password ], 401);

        $userRepository = $this->entityManager->getRepository(User::class);
        $user = $userRepository->findOneBy(['username' => $username]);

        if (!$user || $user->getPassword() !== $password) {
            return new JsonResponse(['error' => 'Invalid credentials'], 401);
        }

        $token = $this->jwtService->createToken(['username' => $user->getUsername(), 'exp' => time() + 3600]);

        return new JsonResponse(['token' => $token]);
    }
}