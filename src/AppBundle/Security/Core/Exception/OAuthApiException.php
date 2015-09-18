<?php
namespace AppBundle\Security\Core\Exception;

use HWI\Bundle\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;
use HWI\Bundle\OAuthBundle\Security\Core\Exception\OAuthAwareExceptionInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * Class OAuthApiException
 * @package AppBundle\Security\Core\Exception
 */
class OAuthApiException extends \Exception implements OAuthAwareExceptionInterface
{
    /**
     * @var string
     */
    protected $resourceOwnerName;

    /**
     * @var OAuthToken
     */
    protected $token;

    /**
     * Get the access token information.
     *
     * @return string
     */
    public function getAccessToken()
    {
        return $this->token->getAccessToken();
    }

    /**
     * Get the raw version of received token.
     *
     * @return array
     */
    public function getRawToken()
    {
        return $this->token->getRawToken();
    }

    /**
     * Get the refresh token information.
     *
     * @return null|string
     */
    public function getRefreshToken()
    {
        return $this->token->getRefreshToken();
    }

    /**
     * Get the info when token will expire.
     *
     * @return null|integer
     */
    public function getExpiresIn()
    {
        return $this->token->getExpiresIn();
    }

    /**
     * Get the oauth secret token
     *
     * @return null|string
     */
    public function getTokenSecret()
    {
        return $this->token->getTokenSecret();
    }

    /**
     * Set the token.
     *
     * @param TokenInterface $token
     */
    public function setToken(TokenInterface $token)
    {
        $this->token = $token;
    }

    /**
     * Set the name of the resource owner responsible for the oauth authentication.
     *
     * @param string $resourceOwnerName
     */
    public function setResourceOwnerName($resourceOwnerName)
    {
        $this->resourceOwnerName = $resourceOwnerName;
    }

    /**
     * Get the name of resource owner.
     *
     * @return string
     */
    public function getResourceOwnerName()
    {
        return $this->resourceOwnerName;
    }
}