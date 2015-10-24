<?php
namespace AppBundle\DependencyInjection\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\DependencyInjection\Parameter;

/**
 * Class OAuthApiFactory
 * @package AppBundle\DependencyInjection\Security\Factory
 */
class OAuthApiFactory implements SecurityFactoryInterface
{
    public function getPosition()
    {
        return 'http';
    }

    public function getKey()
    {
        return 'oauth-api';
    }

    public function addConfiguration(NodeDefinition $node)
    {
    }

    public function create(ContainerBuilder $container, $id, $config, $userProvider, $defaultEntryPoint)
    {
        $providerId = 'oauth2.security.authentication.provider.'.$id;

        $container
            ->setDefinition($providerId, new DefinitionDecorator('oauth2.security.authentication.provider'))
            ->replaceArgument(0, new Reference($userProvider))
        ;

        $listenerId = 'oauth2.security.authentication.listener.'.$id;

        $listener = $container->setDefinition($listenerId, new DefinitionDecorator('oauth2.security.authentication.listener'));

        return [$providerId, $listenerId, $defaultEntryPoint];
    }
}
