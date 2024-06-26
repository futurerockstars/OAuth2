<?php
namespace Drahak\OAuth2\DI;

use Nette\Configurator;
use Nette\DI\CompilerExtension;
use Nette\DI\ContainerBuilder;
use Nette\DI\Definitions\ServiceDefinition;
use Nette\Schema\Expect;
use Nette\Schema\Schema;

/**
 * OAuth2 compiler extension
 * @package Drahak\OAuth2\DI
 * @author Drahomír Hanák
 */
class Extension extends CompilerExtension
{

	protected $storages = array(
		'ndb' => array(
			'accessTokenStorage' => 'Drahak\OAuth2\Storage\NDB\AccessTokenStorage',
			'authorizationCodeStorage' => 'Drahak\OAuth2\Storage\NDB\AuthorizationCodeStorage',
			'clientStorage' => 'Drahak\OAuth2\Storage\NDB\ClientStorage',
			'refreshTokenStorage' => 'Drahak\OAuth2\Storage\NDB\RefreshTokenStorage',
		),
		'dibi' => array(
			'accessTokenStorage' => 'Drahak\OAuth2\Storage\Dibi\AccessTokenStorage',
			'authorizationCodeStorage' => 'Drahak\OAuth2\Storage\Dibi\AuthorizationCodeStorage',
			'clientStorage' => 'Drahak\OAuth2\Storage\Dibi\ClientStorage',
			'refreshTokenStorage' => 'Drahak\OAuth2\Storage\Dibi\RefreshTokenStorage',
		),
	);

	public function getConfigSchema(): Schema
	{
		return Expect::structure([
			'accessTokenStorage' => Expect::anyOf(Expect::string(), Expect::null())->default(null),
			'authorizationCodeStorage' => Expect::anyOf(Expect::string(), Expect::null())->default(null),
			'clientStorage' => Expect::anyOf(Expect::string(), Expect::null())->default(null),
			'refreshTokenStorage' => Expect::anyOf(Expect::string(), Expect::null())->default(null),
			'accessTokenLifetime' => Expect::int(3600), // 1 hour
			'refreshTokenLifetime' => Expect::int(36000), // 10 hours
			'authorizationCodeLifetime' => Expect::int(360), // 6 minutes
			'storage' => Expect::anyOf(Expect::string(), Expect::null())->default(null),
		])->castTo('array');
	}

	/**
	 * Load DI configuration
	 */
	public function loadConfiguration()
	{
		$container = $this->getContainerBuilder();
		$config = $this->config;

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

		// Default fallback value
		$storageIndex = 'ndb';

		// Nette database Storage
		if (strtoupper($config['storage']) == 'NDB' || (is_null($config['storage']) && $this->getByType($container, 'Nette\Database\Context'))) {
			$storageIndex = 'ndb';
		} elseif (strtoupper($config['storage']) == 'DIBI' || (is_null($config['storage']) && $this->getByType($container, 'DibiConnection'))) {
			$storageIndex = 'dibi';
		}

		$container->addDefinition($this->prefix('accessTokenStorage'))
			->setClass($config['accessTokenStorage'] ?: $this->storages[$storageIndex]['accessTokenStorage']);
		$container->addDefinition($this->prefix('refreshTokenStorage'))
			->setClass($config['refreshTokenStorage'] ?: $this->storages[$storageIndex]['refreshTokenStorage']);
		$container->addDefinition($this->prefix('authorizationCodeStorage'))
			->setClass($config['authorizationCodeStorage'] ?: $this->storages[$storageIndex]['authorizationCodeStorage']);
		$container->addDefinition($this->prefix('clientStorage'))
			->setClass($config['clientStorage'] ?: $this->storages[$storageIndex]['clientStorage']);
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
			if ($definition instanceof ServiceDefinition && $definition->class === $type) {
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