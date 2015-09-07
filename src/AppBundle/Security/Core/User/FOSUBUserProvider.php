<?php
namespace AppBundle\Security\Core\User;

use HWI\Bundle\OAuthBundle\OAuth\Response\UserResponseInterface;
use HWI\Bundle\OAuthBundle\Security\Core\User\FOSUBUserProvider as BaseClass;
use Symfony\Component\Security\Core\User\UserInterface;
use Doctrine\Common\Util\Inflector as Inflector;

class FOSUBUserProvider extends BaseClass
{
    /**
     * {@inheritdoc}
     */
    public function loadUserByOAuthUserResponse(UserResponseInterface $response)
    {
        $user_id = $response->getUsername();
        $username = $response->getNickname();

        $service = $response->getResourceOwner()->getName();
        $setter = 'set_'.ucfirst($service);
        $setter_id = Inflector::camelize($setter.'_id');
        $setter_token = Inflector::camelize($setter.'_AccessToken');

        $user = $this->userManager->findUserBy(array($service.'_id' => $user_id));
        //when the user is registrating
        if (null === $user) {
            // create new user here
            $user = $this->userManager->createUser();
            $user->$setter_id($user_id);
            $user->$setter_token($response->getAccessToken());
            //I have set all requested data with the user's username
            //modify here with relevant data
            $user->setUsername($username);
            $user->setEmail($user_id);
            $user->setPassword($user_id);
            $user->setEnabled(true);
            $this->userManager->updateUser($user);
            return $user;
        }
        //if user exists - go with the HWIOAuth way
        $user = parent::loadUserByOAuthUserResponse($response);
        $serviceName = $response->getResourceOwner()->getName();
        //update access token
        $user->$setter_token($response->getAccessToken());
        return $user;
    }
}