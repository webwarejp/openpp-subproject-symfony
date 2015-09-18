<?php
namespace AppBundle\Controller\Api;

use Symfony\Component\HttpFoundation\JsonResponse;

class UsersController
{
    /**
     *
     * @param $slug
     */
    public function getUserAction($slug)
    {
        return new JsonResponse(['hello' => $slug]);
    }

    /**
     *
     * @param $slug
     */
    public function postUserAction($slug)
    {
        return new JsonResponse(['hello' => $slug]);
    }

}