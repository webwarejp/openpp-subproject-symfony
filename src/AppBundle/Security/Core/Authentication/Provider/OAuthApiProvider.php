<?php

namespace AppBundle\Security\Core\Authentication\Provider;

use HWI\Bundle\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;
use HWI\Bundle\OAuthBundle\Security\Core\Exception\OAuthAwareExceptionInterface;
use HWI\Bundle\OAuthBundle\Security\Core\User\OAuthAwareUserProviderInterface;
use HWI\Bundle\OAuthBundle\OAuth\ResourceOwner\AbstractResourceOwner;
use HWI\Bundle\OAuthBundle\Security\Http\ResourceOwnerMap;
use HWI\Bundle\OAuthBundle\Security\Core\Exception\AccountNotLinkedException;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\HttpFoundation\Request;
use AppBundle\Security\Core\Exception\OAuthApiException;


/**
 * Class OAuthApiProvider
 * @package AppBundle\Security\Core\Authentication\Provider
 */
class OAuthApiProvider implements AuthenticationProviderInterface
{
    /**
     * @var AbstractResourceOwner
     */
    private $resourceOwnerMap;

    /**
     * @var OAuthAwareUserProviderInterface
     */
    private $userProvider;

    /**
     * @var UserCheckerInterface
     */
    private $userChecker;

    /**
     * @param OAuthAwareUserProviderInterface $userProvider     User provider
     * @param AbstractResourceOwner           $resourceOwner Resource owner map
     * @param UserCheckerInterface            $userChecker      User checker
     */
    public function __construct(OAuthAwareUserProviderInterface $userProvider, ResourceOwnerMap $resourceOwnerMap, UserCheckerInterface $userChecker)
    {
        $this->userProvider     = $userProvider;
        $this->resourceOwnerMap = $resourceOwnerMap;
        $this->userChecker      = $userChecker;
    }

    /**
     * {@inheritDoc}
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof OAuthToken;
    }

    /**
     * OAuthサーバーのuserinfoを取得する。
     *
     * OAuthApiListener から呼ばれる。
     * 正常時はユーザーを取得。内部で、会員登録、 access token の更新を行う。
     * エラー時はOAuthApiException を投げることで、authenticate manager の loop から抜ける。
     *
     * @param TokenInterface $token
     * @return OAuthToken|TokenInterface
     * @throws OAuthAwareExceptionInterface
     * @throws \Exception
     */
    public function authenticate(TokenInterface $token)
    {
        try {
            $resouceOwnerName = $token->getResourceOwnerName();
            /* @var OAuthToken $token */
            $response = $this->resourceOwnerMap->getResourceOwnerByName($resouceOwnerName)->getUserInformation($token->getRawToken());
            $rowResponse = $response->getResponse();
            if (isset($rowResponse['error'])) {
                throw new OAuthApiException(sprintf("%s: %s.", $rowResponse['error'], $rowResponse['error_description']));
            } else {
                $user = $this->userProvider->loadUserByOAuthUserResponse($response);
            }
        } catch (OAuthAwareExceptionInterface $e) {
            $e->setToken($token);
            $e->setResourceOwnerName($token->getResourceOwnerName());
            throw $e;
        }
        $token = new OAuthToken($token->getRawToken(), $user->getRoles());
        $token->setResourceOwnerName($this->resourceOwnerMap->getResourceOwnerByName('my_custom')->getName());
        $token->setUser($user);
        $token->setAuthenticated(true);

        $this->userChecker->checkPostAuth($user);

        return $token;
    }
}