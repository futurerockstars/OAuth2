<?php
namespace Drahak\OAuth2\Grant;

use Drahak\OAuth2\Storage\ITokenFacade;

/**
 * Implicit grant type
 * @package Drahak\OAuth2\Grant
 * @author Drahomír Hanák
 */
class Implicit extends GrantType
{

	/**
	 * Get identifier string to this grant type
	 * @return string
	 */
	public function getIdentifier()
	{
		return self::IMPLICIT;
	}

	/**
	 * Verify grant type
	 */
	protected function verifyGrantType()
	{
	}

	/**
	 * Verify request
	 * @return void
	 */
	protected function verifyRequest()
	{
	}

	/**
	 * Generate access token
	 * @return string
	 */
	protected function generateAccessToken(): array
	{
		$accessTokenStorage = $this->token->getToken(ITokenFacade::ACCESS_TOKEN);
		$accessToken = $accessTokenStorage->create($this->getClient(), $this->user->getId(), $this->getScope());

		return array(
			'access_token' => $accessToken->getAccessToken(),
			'expires_in' => $accessTokenStorage->getLifetime(),
			'token_type' => 'bearer'
		);
	}

}