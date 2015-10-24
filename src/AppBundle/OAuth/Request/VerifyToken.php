<?php
namespace AppBundle\OAuth\Request;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use HWI\Bundle\OAuthBundle\Security\Core\Authentication\Token\OAuthToken;
use Buzz\Client\ClientInterface as HttpClientInterface;
use Buzz\Message\Request as HttpRequest;
use Buzz\Message\RequestInterface as HttpRequestInterface;
use Buzz\Message\Response as HttpResponse;
use Doctrine\ORM\EntityManager;
use AppBundle\Entity\Client;

/**
 * Class VerifyToken
 * @package AppBundle\OAuth\Request
 */
class VerifyToken
{
    /**
     * @var HttpClientInterface
     */
    protected $httpClient;

    /**
     * @var string
     */
    protected $verify_url;

    /**
     * @param HttpClientInterface $httpClient
     * @param EntityManager $entityManager
     * @param string $verify_url
     */
    public function __construct(HttpClientInterface $httpClient, EntityManager $entityManager, $verify_url)
    {
        $this->httpClient    = $httpClient;
        $this->entityManager = $entityManager;
        $this->verify_url    = $verify_url;
    }
    /**
     * ユーザーをclient id/secret/access tokenから取得
     * 既存clientでexpireの制限内ならそれ以降のチェックはしない。
     *
     * httpRequest response
     * onSuccess:
     * {"result":true,"user_id":xxx,"expires_at":xxxxxxx}
     *
     * onFailer:
     * openpp oauth token check failed.
     * {error: xxxx , error_description: xxxx}
     *
     * openpp internal error.
     * {"code":500,"message": "xxxxxx"}
     *
     * verify endpoint return false
     * {"result":false,"err":"0","err_msg":"user not found"}
     *
     * @param $token TokenInterface
     * @return array
     */
    public function verify(TokenInterface $token)
    {
        //retrieve client from local
        /* @var $client Client */
        $client = $this->entityManager->getRepository('AppBundle:Client')->findByClientAndToken($token->getAccessToken(), $token->getAttribute('client_id'), $token->getAttribute('client_secret'));
        if($client != null)
        {
            if($client->getExpired()->getTimestamp() < time())
            {
                $this->entityManager->remove($client);
                $this->entityManager->flush();
            }
            else
            {
                $return = [
                    'result'=> true
                    , 'user_id' => $client->getUser()
                    , 'expires_at' => $client->getExpired()
                ];
                return $return;
            }
        }

        /* @var OAuthToken $token */
        $data = [
            'client_id' => $token->getAttribute('client_id')
            , 'client_secret' => $token->getAttribute('client_secret')
            , 'access_token' => $token->getAccessToken()
        ];

        $content = $this->httpRequest($this->verify_url, json_encode($data), ['Authorization: Bearer ' . $token->getAccessToken()]);
        $response = $content->getContent() ? json_decode($content->getContent()) : [];
        if (isset($response->error)) { //oauth headerで弾かれた場合
            $return = [
                'result' => false
                , 'code' => 100
                , 'error' => $response->error
                , 'error_description' => $response->error_description
            ];
        } else if (isset($response->code)) { //symfonyエラー
            $return = [
                'result' => false
                , 'code' => 101
                , 'error' => $response->code
                , 'error_description' => $response->message
            ];
        }else if (isset($response->result)) {
            if($response->result == true)
            {
                $return = [
                    'result'=> true
                    , 'user_id' => $response->user_id
                    , 'expires_at' => $response->expires_at
                ];
            }else{
                $return = [
                    'result'=> false
                    , 'code' => 102
                    , 'error' => $response->err
                    , 'error_description' => $response->err_msg
                ];
            }
        }else{
            $return = [
                'result'=> false
                , 'code' => 103
                , 'error' => null
                , 'error_description' => 'internal server error.'
            ];
        }
        return $return;
    }


    /**
     * {@inheritDoc}
     */
    public function getUserInformation(array $accessToken, array $extraParameters = [])
    {
        if ($this->options['use_bearer_authorization']) {
            $url = $this->normalizeUrl($this->options['infos_url']);

            $content = $this->httpRequest($url, null, ['Authorization: Bearer '.$accessToken['access_token']]);
        } else {
            $url = $this->normalizeUrl($this->options['infos_url'], ['access_token' => $accessToken['access_token']]);

            $content = $this->doGetUserInformationRequest($url);
        }

        $response = $this->getUserResponse();
        $response->setResponse($content->getContent());
        $response->setResourceOwner($this);
        $response->setOAuthToken(new OAuthToken($accessToken));

        return $response;
    }

    /**
     * copy from HWI\Bundle\OAuthBundle\OAuth\ResourceOwner::httpRequest
     *
     * @param string $url     The url to fetch
     * @param string $content The content of the request
     * @param array  $headers The headers of the request
     * @param string $method  The HTTP method to use
     *
     * @return HttpResponse The response content
     */
    protected function httpRequest($url, $content = null, $headers = [], $method = null)
    {
        if (null === $method) {
            $method = null === $content ? HttpRequestInterface::METHOD_GET : HttpRequestInterface::METHOD_POST;
        }

        $request  = new HttpRequest($method, $url);
        $response = new HttpResponse();

        $headers = array_merge(
            [
                'User-Agent: OpenPPOAuthClient (https://github.com/webwarejp/openpp)',
            ],
            $headers
        );

        $request->setHeaders($headers);
        $request->setContent($content);

        $this->httpClient->send($request, $response);

        return $response;
    }


}