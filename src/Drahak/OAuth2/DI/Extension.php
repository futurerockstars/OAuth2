<?php
namespace Drahak\OAuth2\DI;

use Nette\Configurator;
use Nette\DI\CompilerExtension;
use Nette\DI\ContainerBuilder;
use Nette\DI\ServiceDefinition;

/**
 * OAuth2 compiler extension
 * @package Drahak\OAuth2\DI
 * @author Drahomír Hanák
 */
class Extension extends CompilerExtension
{

	/**
	 * Default DI settings
	 * @var array
	 */
	protected $defaults = array(
		'accessTokenLifetime' => 3600, // 1 hour
		'refreshTokenLifetime' => 36000, // 10 hours
		'authorizationCodeLifetime' => 360 // 6 minutes
	);

	/**
	 * Load DI configuration
	 */
	public function loadConfiguration()
	{
		$container = $this->getContainerBuilder();
		$config = $this->getConfig($this->defaults);

		// Library common
		$container->addDefinition($this->prefix('keyGenerator'))
			->setClass('Drahak\OAuth2\KeyGenerator');

		$container->addDefinition($this->prefix('input'))
			->setClass('Drahak\OAuth2\Http\Input');

		// Grant types
		$container->addDefinition($this->prefix('authorizationCodeGrant'))
			->setClass('Drahak\OAuth2\Grant\AuthorizationCode');
		$container->addDefinition($this->prefix('refreshTokenGrant'))
			->setClass('Drahak\OAuth2\Grant\RefreshToken');
		$container->addDefinition($this->prefix('passwordGrant'))
			->setClass('Drahak\OAuth2\Grant\Password');
		$container->addDefinition($this->prefix('implicitGrant'))
			->setClass('Drahak\OAuth2\Grant\Implicit');
		$container->addDefinition($this->prefix('clientCredentialsGrant'))
			->setClass('Drahak\OAuth2\Grant\ClientCredentials');

		$container->addDefinition($this->prefix('grantContext'))
			->setClass('Drahak\OAuth2\Grant\GrantContext')
			->addSetup('$service->addGrantType(?)', array($this->prefix('@authorizationCodeGrant')))
			->addSetup('$service->addGrantType(?)', array($this->prefix('@refreshTokenGrant')))
			->addSetup('$service->addGrantType(?)', array($this->prefix('@passwordGrant')))
			->addSetup('$service->addGrantType(?)', array($this->prefix('@implicitGrant')))
			->addSetup('$service->addGrantType(?)', array($this->prefix('@clientCredentialsGrant')));

		// Tokens
		$container->addDefinition($this->prefix('accessToken'))
			->setClass('Drahak\OAuth2\Storage\AccessTokens\AccessTokenFacade')
			->setArguments(array($config['accessTokenLifetime']));
		$container->addDefinition($this->prefix('refreshToken'))
			->setClass('Drahak\OAuth2\Storage\RefreshTokens\RefreshTokenFacade')
			->setArguments(array($config['refreshTokenLifetime']));
		$container->addDefinition($this->prefix('authorizationCode'))
			->setClass('Drahak\OAuth2\Storage\AuthorizationCodes\AuthorizationCodeFacade')
			->setArguments(array($config['authorizationCodeLifetime']));

		$container->addDefinition('tokenContext')
			->setClass('Drahak\OAuth2\Storage\TokenContext')
			->addSetup('$service->addToken(?)', array($this->prefix('@accessToken')))
			->addSetup('$service->addToken(?)', array($this->prefix('@refreshToken')))
			->addSetup('$service->addToken(?)', array($this->prefix('@authorizationCode')));

		// Nette database Storage
		if ($this->getByType($container, 'Nette\Database\Context')) {
			$container->addDefinition($this->prefix('accessTokenStorage'))
				->setClass('Drahak\OAuth2\Storage\NDB\AccessTokenStorage');
			$container->addDefinition($this->prefix('refreshTokenStorage'))
				->setClass('Drahak\OAuth2\Storage\NDB\RefreshTokenStorage');
			$container->addDefinition($this->prefix('authorizationCodeStorage'))
				->setClass('Drahak\OAuth2\Storage\NDB\AuthorizationCodeStorage');
			$container->addDefinition($this->prefix('clientStorage'))
				->setClass('Drahak\OAuth2\Storage\NDB\ClientStorage');
		}
	}

	/**
	 * @param ContainerBuilder $container
	 * @param string $type
	 * @return ServiceDefinition|null
	 */
	private function getByType(ContainerBuilder $container, $type)
	{
		$definitionas = $container->getDefinitions();
		foreach ($definitionas as $definition) {
			if ($definition->class === $type) {
				return $definition;
			}
		}
		return NULL;
	}

	/**
	 * Register OAuth2 extension
	 * @param Configurator $configurator
	 */
	public static function install(Configurator $configurator)
	{
		$configurator->onCompile[] = function($configurator, $compiler) {
			$compiler->addExtension('oauth2', new Extension);
		};
	}

}