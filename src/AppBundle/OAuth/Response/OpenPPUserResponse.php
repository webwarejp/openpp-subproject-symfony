<?php
namespace AppBundle\OAuth\Response;

use HWI\Bundle\OAuthBundle\OAuth\Response\PathUserResponse;

class OpenPPUserResponse extends PathUserResponse
{
    /**
     *
     */
    public function getTokenClientId()
    {
        if($this->oAuthToken->hasAttribute('client_id'))
        {
            return $this->oAuthToken->getAttribute('client_id');
        }
        return null;
    }

    /**
     *
     */
    public function getTokenClientSecret()
    {
        if($this->oAuthToken->hasAttribute('client_secret'))
        {
            return $this->oAuthToken->getAttribute('client_secret');
        }
        return null;
    }

}