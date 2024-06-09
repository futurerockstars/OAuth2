<?php
namespace Drahak\OAuth2\Grant;

use Drahak\OAuth2\InvalidRequestException;
use Drahak\OAuth2\InvalidStateException;
use Drahak\OAuth2\Storage\ITokenFacade;
use Nette\Security\AuthenticationException;

/**
 * Password grant type
 * @package Drahak\OAuth2\Grant
 * @author Drahomír Hanák
 */
class Password extends GrantType
{

	/**
	 * Get identifier string to this grant type
	 * @return string
	 */
	public function getIdentifier()
	{
		return self::PASSWORD;
	}

	/**
	 * Verify request
	 *
	 * @throws InvalidStateException
	 * @throws AuthenticationException
	 */
	protected function verifyRequest()
	{
		$password = $this->input->getParameter('password');
		$username = $this->input->getParameter('username');
		if (!$password || !$username) {
			throw new InvalidStateException;
		}

		try {
			$this->user->login($username, $password);
		} catch(AuthenticationException $e) {
			throw new InvalidRequestException('Wrong user credentials', $e);
		}
	}

	/**
	 * Generate access token
	 */
	protected function generateAccessToken(): array
	{
		$accessTokenStorage = $this->token->getToken(ITokenFacade::ACCESS_TOKEN);
		$refreshTokenStorage = $this->token->getToken(ITokenFacade::REFRESH_TOKEN);

		$accessToken = $accessTokenStorage->create($this->getClient(), $this->user->getId(), $this->getScope());
		$refreshToken = $refreshTokenStorage->create($this->getClient(), $this->user->getId(), $this->getScope());

		return array(
			'access_token' => $accessToken->getAccessToken(),
			'expires_in' => $accessTokenStorage->getLifetime(),
			'token_type' => 'bearer',
			'refresh_token' => $refreshToken->getRefreshToken()
		);
	}

}