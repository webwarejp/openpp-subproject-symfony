<?php
namespace AppBundle\Security\Core\User;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\PropertyAccess\PropertyAccess;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use HWI\Bundle\OAuthBundle\OAuth\Response\UserResponseInterface;
use HWI\Bundle\OAuthBundle\Security\Core\User\FOSUBUserProvider;
use HWI\Bundle\OAuthBundle\Security\Core\User\OAuthAwareUserProviderInterface;
use AppBundle\Entity\User;
use AppBundle\Entity\Client;
use AppBundle\OAuth\Response\OpenPPUserResponse;
use AppBundle\Security\Core\Authentication\Token\OAuthApiToken;

/**
 * Class FOSUBUserProvider
 * @package AppBundle\Security\Core\User
 */
class OpenPPUserProvider extends FOSUBUserProvider implements OAuthAwareUserProviderInterface
{
    /**
     * retrive user by verify endpoint's response , token(client id/secret/access token)
     *
     * @param TokenInterface $token
     * @param array $verifyResult
     * @return User
     */
    public function loadUserByOAuthVerifyResponse(TokenInterface $token, array $verifyResult)
    {
        $user_id = $verifyResult['user_id'];
        /* @var $user User */
        $user = $this->userManager->findUserBy(['pp_user_id' => $user_id]);

        if($user)
        {
            /* @var $token OAuthApiToken */
            $access_token = $token->getAccessToken();
            $client_id = $token->getAttribute('client_id');
            $client_secret = $token->getAttribute('client_secret');
            /* @var $client Client */
            $collection = $user->getClients()->filter(function($entity) use($access_token, $client_id, $client_secret){
                if($entity->getAccessToken() == $access_token
                    && $entity->getClientId() == $client_id
                    && $entity->getClientSecret() == $client_secret){
                    return true;
                }
            });
            $client = $collection->first();

            if($client == null)
            {
                $expires = new \DateTime();
                $expires->setTimestamp($verifyResult['expires_at']);
                $client = new Client();
                $client->setAccessToken($access_token);
                $client->setClientId($client_id);
                $client->setClientSecret($client_secret);
                $client->setExpired($expires);
                $client->setUser($user);
                $user->getClients()->add($client);
                $this->userManager->updateUser($user);
            }
        }
        return $user;
    }

    /**
     * ユーザーがいたらユーザーを返す。client の access_token が違っていたらリクエストの access_token で上書きする。
     * ユーザーがいなかったら新規作成する。clinet も追加する。
     *
     * @param $response OpenPPUserResponse
     */
    public function loadUserByOAuthUserResponse(UserResponseInterface $response)
    {

        $user_id = $response->getUsername();

        /* @var $user User */
        $user = $this->userManager->findUserBy(['pp_user_id' => $user_id]);
        //when the user is registrating
        if (null === $user) {
            // create new user here
            $user = $this->userManager->createUser();
            $user->setPpUserId($user_id);

            if($response->getTokenClientId() && $response->getTokenClientSecret())
            {
                $client = new Client();
                $client->setAccessToken($response->getAccessToken());
                $client->setClientId($response->getTokenClientId());
                $client->setClientSecret($response->getTokenClientSecret());
                $client->setUser($user);
                $user->getClients()->add($client);
            }

            //I have set all requested data with the user's username
            //modify here with relevant data
            $user->setUsername($response->getNickname());
            $user->setEmail($user_id);
            $user->setPassword($user_id);
            $user->setEnabled(true);
            $this->userManager->updateUser($user);
            return $user;
        }
        else
        {
            if($response->getTokenClientId() && $response->getTokenClientSecret())
            {
                /* @var $client Client */
                $client = $user->getClients()->contains(['client_secret' => $response->getTokenClientId()
                    , 'client_id' => $response->getTokenClientSecret()]);
                if($client != null && $client->getAccessToken() != $response->getAccessToken())
                {
                    //update access token
                    $client->setAccessToken($response->getAccessToken());
                }
            }
        }

        return $user;
    }

}
