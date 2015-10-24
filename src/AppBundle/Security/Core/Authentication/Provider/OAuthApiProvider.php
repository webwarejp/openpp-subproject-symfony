<?php

namespace AppBundle\Security\Core\Authentication\Provider;

use HWI\Bundle\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;
use HWI\Bundle\OAuthBundle\Security\Core\Exception\OAuthAwareExceptionInterface;
use HWI\Bundle\OAuthBundle\Security\Core\User\OAuthAwareUserProviderInterface;
use HWI\Bundle\OAuthBundle\OAuth\ResourceOwner\AbstractResourceOwner;
use HWI\Bundle\OAuthBundle\Security\Http\ResourceOwnerMap;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use AppBundle\Security\Core\Exception\OAuthApiException;
use AppBundle\Security\Core\Authentication\Token\OAuthApiToken;
use AppBundle\OAuth\Request\VerifyToken;

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
     * @var VerifyToken
     */
    private $verifyToken;

    /**
     * @param OAuthAwareUserProviderInterface $userProvider     User provider
     * @param AbstractResourceOwner           $resourceOwner Resource owner map
     * @param UserCheckerInterface            $userChecker      User checker
     */
    public function __construct(OAuthAwareUserProviderInterface $userProvider, ResourceOwnerMap $resourceOwnerMap, UserCheckerInterface $userChecker, VerifyToken $verifyToken)
    {
        $this->userProvider     = $userProvider;
        $this->resourceOwnerMap = $resourceOwnerMap;
        $this->userChecker      = $userChecker;
        $this->verifyToken      = $verifyToken;
    }

    /**
     * {@inheritDoc}
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof OAuthApiToken;
    }

    /**
     * OAuthサーバーのuserinfoを取得する。
     *
     * OAuthApiListener から呼ばれる。
     * はじめにaccess_token, client_id, client_secretの組み合わせのチェックを行う。
     * 正常時はユーザーを取得。内部で、会員登録、 access token の更新を行う。
     * エラー時はOAuthApiException を投げることで、authenticate manager の loop から抜ける。
     *
     * @param TokenInterface $token
     * @return OAuthApiToken|TokenInterface
     * @throws OAuthAwareExceptionInterface
     * @throws \Exception
     */
    public function authenticate(TokenInterface $token)
    {
        $resouceOwnerName = $token->getResourceOwnerName();
        try {
            $resourceOwner = $this->resourceOwnerMap->getResourceOwnerByName($resouceOwnerName);

            //ローカルの client id/secret/token の組み合わせをチェックして、ユーザーを取得。
            $verifyResult = $this->verifyToken->verify($token);
            if(isset($verifyResult['result']) && $verifyResult['result'] == true)
            {
                $user = $this->userProvider->loadUserByOAuthVerifyResponse($token, $verifyResult);
                if(! $user)
                {
                    /* @var OAuthApiToken $token */
                    $response = $resourceOwner->getUserInformation($token->getRawToken());
                    $rowResponse = $response->getResponse();
                    if (isset($rowResponse['error'])) {
                        throw new OAuthApiException($rowResponse['error_description'], is_int($rowResponse['error']) ? $rowResponse['error'] : null);
                    } else {
                        $user = $this->userProvider->loadUserByOAuthUserResponse($response);
                    }
                }
            }
            else
            {
                throw new OAuthApiException($verifyResult['error_description'], $verifyResult['code']);
            }
        } catch (OAuthAwareExceptionInterface $e) {
            $e->setToken($token);
            $e->setResourceOwnerName($token->getResourceOwnerName());
            throw $e;
        }
        $token = new OAuthToken($token->getRawToken(), $user->getRoles());
        $token->setResourceOwnerName($resouceOwnerName);
        $token->setUser($user);
        $token->setAuthenticated(true);

        $this->userChecker->checkPostAuth($user);

        return $token;
    }
}
