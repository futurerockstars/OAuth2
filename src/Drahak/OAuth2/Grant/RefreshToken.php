<?php
namespace Drahak\OAuth2\Grant;

use Drahak\OAuth2\Storage\InvalidRefreshTokenException;
use Drahak\OAuth2\Storage\ITokenFacade;

/**
 * RefreshToken
 * @package Drahak\OAuth2\Grant
 * @author Drahomír Hanák
 */
class RefreshToken extends GrantType
{
	/**
	 * Get refresh token identifier
	 * @return string
	 */
	public function getIdentifier()
	{
		return self::REFRESH_TOKEN;
	}

	/**
	 * Verify request
	 *
	 * @throws InvalidRefreshTokenException
	 */
	protected function verifyRequest()
	{
		$refreshTokenStorage = $this->token->getToken(ITokenFacade::REFRESH_TOKEN);
		$refreshToken = $this->input->getParameter('refresh_token');

		$refreshTokenStorage->getEntity($refreshToken);
		$refreshTokenStorage->getStorage()->remove($refreshToken);
	}

	/**
	 * Generate access token
	 */
	protected function generateAccessToken(): array
	{
		$accessTokenStorage = $this->token->getToken(ITokenFacade::ACCESS_TOKEN);
		$refreshTokenStorage = $this->token->getToken(ITokenFacade::REFRESH_TOKEN);

		$accessToken = $accessTokenStorage->create($this->getClient(), $this->user->getId());
		$refreshToken = $refreshTokenStorage->create($this->getClient(), $this->user->getId());

		return array(
			'access_token' => $accessToken->getAccessToken(),
			'token_type' => 'bearer',
			'expires_in' => $accessTokenStorage->getLifetime(),
			'refresh_token' => $refreshToken->getRefreshToken()
		);
	}


}