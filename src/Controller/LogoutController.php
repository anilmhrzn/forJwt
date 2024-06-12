<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class LogoutController extends AbstractController
{
    #[Route('/logout', name: 'app_logout', methods: ['GET'])]
    public function logout(AuthenticationUtils $authenticationUtils): Response
    {
        // Get the current user
        $user = $this->getUser();

        // If the user is already logged out, redirect them to the login page
        if (!$user) {
            return $this->redirectToRoute('app_login');
        }

        // Logout the user
        $authenticationUtils->logout();

        // Redirect the user to the login page
        return $this->redirectToRoute('app_login');
    }
}