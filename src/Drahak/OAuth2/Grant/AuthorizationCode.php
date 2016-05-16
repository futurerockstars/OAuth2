<?php
namespace Drahak\OAuth2\Grant;

use Drahak\OAuth2\Storage;
use Drahak\OAuth2\Storage\AccessToken;
use Drahak\OAuth2\Storage\RefreshTokenFacade;
use Drahak\OAuth2\Storage\ITokenFacade;

/**
 * AuthorizationCode
 * @package Drahak\OAuth2\Grant
 * @author Drahomír Hanák
 */
class AuthorizationCode extends GrantType
{

	/** @var array */
	private $scope = array();

	/** @var Storage\AuthorizationCodes\AuthorizationCode */
	private $entity;

	/**
	 * @return array
	 */
	protected function getScope()
	{
		return $this->scope;
	}

	/**
	 * Get authorization code identifier
	 * @return string
	 */
	public function getIdentifier()
	{
		return self::AUTHORIZATION_CODE;
	}

	/**
	 * Verify request
	 * @throws Storage\InvalidAuthorizationCodeException
	 */
	protected function verifyRequest()
	{
		$code = $this->input->getParameter('code');

		$this->entity = $this->token->getToken(ITokenFacade::AUTHORIZATION_CODE)->getEntity($code);
		$this->scope = $this->entity->getScope();

		$this->token->getToken(ITokenFacade::AUTHORIZATION_CODE)->getStorage()->remove($code);
	}

	/**
	 * Generate access token
	 * @return string
	 */
	protected function generateAccessToken()
	{
		$client = $this->getClient();
		$accessTokenStorage = $this->token->getToken(ITokenFacade::ACCESS_TOKEN);
		$refreshTokenStorage = $this->token->getToken(ITokenFacade::REFRESH_TOKEN);

		$accessToken = $accessTokenStorage->create($client, $this->user->getId() ?: $this->entity->getUserId(), $this->getScope());
		$refreshToken = $refreshTokenStorage->create($client, $this->user->getId() ?: $this->entity->getUserId(), $this->getScope());

		return array(
			'access_token' => $accessToken->getAccessToken(),
			'token_type' => 'bearer',
			'expires_in' => $accessTokenStorage->getLifetime(),
			'refresh_token' => $refreshToken->getRefreshToken()
		);
	}

}