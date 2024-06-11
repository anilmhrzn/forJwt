<?php

namespace App\Controller;

use App\Form\UserType;
use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class LoginController extends AbstractController
{
    #[Route('/login', name: 'app_login')]
    public function index(Request $request, UserRepository $userRepository):JsonResponse
    {
//        $form = $this->createForm(UserType::class);
//        $form->handleRequest($request);
//            $data = $form->getData();
//            $username = $data->getUsername();
//            $password = $data->getPassword();
//            $user = $userRepository->findOneBy(['username' => $username]);
//return $this->json(['message' => $request] );
//            if ($user && $user->getPassword() === $password) {
//                return $this->json(['message' => 'success'], Response::HTTP_UNAUTHORIZED);
//
//            }
//        , [
//        'user' => $user,
//        'form' => $form,
//    ]
        // Get the POST parameters
        $username = $request->request->get('username');
        $password = $request->request->get('password');

        // Find the user in the database
        $user = $userRepository->findOneBy(['username' => $username]);

        if ($user && $user->getPassword() === $password) {
            return $this->json(['message' => 'success'], Response::HTTP_OK);
        }

        return $this->json(['message' => 'Invalid credentials'], Response::HTTP_UNAUTHORIZED);

    }
}
