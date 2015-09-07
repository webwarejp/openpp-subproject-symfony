<?php

namespace AppBundle\Entity;

use FOS\UserBundle\Model\User as BaseUser;
use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\Entity
 * @ORM\Table(name="fos_user")
 * @ORM\HasLifecycleCallbacks
 */
class User extends BaseUser
{
    /**
     * @ORM\Id
     * @ORM\Column(type="integer")
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    protected $id;

    /**
     *
     * @var string
     * @ORM\Column(type="string", length=255, nullable=false)
     */
    protected $username;


    /**
     * @var string
     * @ORM\Column(type="integer", unique=true, nullable=false)
     */
    protected $my_custom_id;

    /**
     * @var string
     * @ORM\Column(type="string", length=255, nullable=false)
     */
    protected $my_custom_access_token;

    /**
     * @var \DateTime
     *
     * @ORM\Column(name="created_at", type="datetime", nullable=false)
     */
    protected $createdAt;

    /**
     * @var \DateTime
     *
     * @ORM\Column(name="updated_at", type="datetime", nullable=true)
     */
    protected $updatedAt;

    /**
     *
     */
    public function __construct()
    {
        parent::__construct();
        // your own logic
    }

    /**
     * @param $my_custom_id
     */
    public function setMyCustomId($my_custom_id)
    {
        $this->my_custom_id = $my_custom_id;
    }

    /**
     * @return string
     */
    public function getMyCustomId()
    {
        return $this->my_custom_id;
    }

    /**
     * @param $my_custom_access_token
     */
    public function setMyCustomAccessToken($my_custom_access_token)
    {
        $this->my_custom_access_token = $my_custom_access_token;
    }

    /**
     * @return string
     */
    public function getMyCustomAccessToken()
    {
        return $this->my_custom_access_token;
    }

    /**
     * @ORM\PrePersist
     */
    public function prePersist()
    {
        $this->createdAt = new \DateTime();
    }

    /**
     * set values bedore update
     *
     * @ORM\PreUpdate
     */
    public function preUpdate()
    {
        $this->updatedAt = new \DateTime();
    }
}