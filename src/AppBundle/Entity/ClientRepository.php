<?php
namespace AppBundle\Entity;

use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\Mapping as ORM;
use Doctrine\ORM\Query\Expr\Join;

/**
 * ClientRepository
 *
 */
class ClientRepository extends EntityRepository
{
    /**
     * @param $access_token
     * @param $client_id
     * @param $client_secret
     * @return null|object
     */
    public function findByClientAndToken($access_token, $client_id, $client_secret)
    {
        return $this->findOneBy([
            'client_id' => $client_id
            , 'access_token' => $access_token
            , 'client_secret' => $client_secret
        ]);
    }

}