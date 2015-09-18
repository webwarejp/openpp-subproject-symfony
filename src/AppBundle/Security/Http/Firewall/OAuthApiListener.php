<?php
namespace AppBundle\Security\Http\Firewall;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use HWI\Bundle\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;
use HWI\Bundle\OAuthBundle\Security\Core\Exception\OAuthAwareExceptionInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Psr\Log\LoggerInterface;

/**
 * Class OAuthApiListener
 * @package AppBundle\Security\Http\Firewall
 */
class OAuthApiListener implements ListenerInterface
{

    /**
     * @var TokenStorage
     */
    protected $tokenStorage;
    /**
     * @var AuthenticationManagerInterface
     */
    protected $authenticationManager;
    /**
     * @var LoggerInterface
     */
    protected $logger;
    /**
     * @var
     */
    protected $oauth2_resource_owner_name;

    /**
     * When using the bearer token type, there is a specifc Authorization header
     * required: "Bearer"
     *
     * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-04#section-2.1
     *
     * @var string
     */
    const TOKEN_BEARER_HEADER_NAME = 'Bearer';

    /**
     * @param TokenStorage $tokenStorage
     * @param AuthenticationManagerInterface $authenticationManager
     * @param LoggerInterface|null $logger
     * @param $oauth2_resource_owner_name
     */
    public function __construct(TokenStorage $tokenStorage, AuthenticationManagerInterface $authenticationManager, LoggerInterface $logger = null, $oauth2_resource_owner_name)
    {
        $this->tokenStorage = $tokenStorage;
        $this->authenticationManager = $authenticationManager;
        $this->logger = $logger;
        $this->oauth2_resource_owner_name = $oauth2_resource_owner_name;
    }

    /**
     * firewallの処理
     *
     * @param GetResponseEvent $event
     */
    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        $header = $request->headers->get('Authorization');

        if (!$header) {
            throw new BadCredentialsException('No Bearer token found');
        }

        if (preg_match('/' . preg_quote(self::TOKEN_BEARER_HEADER_NAME, '/') . '\s(\S+)/', $header, $matches)) {
            $accessToken = $matches[1];

            $token = new OAuthToken($accessToken);
            $token->setResourceOwnerName($this->oauth2_resource_owner_name);
            try {
                $returnValue = $this->authenticationManager->authenticate($token);
                if ($returnValue instanceof TokenInterface) {
                    return $this->tokenStorage->setToken($returnValue);
                } else if ($returnValue instanceof Response) {
                    return $event->setResponse($returnValue);
                }
            } catch (AuthenticationException $e) {
                //log
                $this->logger->error(sprintf('Catch Exception,class: %s, line: %s, code: %s, msg: %s', __CLASS__, __LINE__, $e->getCode(), $e->getMessage()));
            } catch (OAuthAwareExceptionInterface $e) {
                //log
                $this->logger->error(sprintf('Catch Exception,class: %s, line: %s, code: %s, msg: %s', __CLASS__, __LINE__, $e->getCode(), $e->getMessage()));
            }
        }
        else
        {
            throw new BadCredentialsException('No Bearer token found');
        }
        $response = new JsonResponse(['code' => $e->getCode(), 'msg' => $e->getMessage()]);
        $response->setStatusCode(403);
        $event->setResponse($response);
    }
}
