module Doorkeeper
  class TokensController < Doorkeeper::ApplicationMetalController
    def create
      response = strategy.authorize
      self.headers.merge! response.headers
      self.response_body = response.body.to_json
      self.status        = response.status
    rescue Errors::DoorkeeperError => e
      handle_token_exception e
    end

    # OAuth 2.0 Token Revocation - http://tools.ietf.org/html/rfc7009
    def revoke
      # The authorization server, if applicable, first authenticates the client
      # and checks its ownership of the provided token.
      #
      # Doorkeeper does not use the token_type_hint logic described in the
      # RFC 7009 due to the refresh token implementation that is a field in
      # the access token model.
      if authorized?
        revoke_token
      end

      # The authorization server responds with HTTP status code 200 if the token
      # has been revoked successfully or if the client submitted an invalid
      # token
      render json: {}, status: 200
    end

    private

    # Modified from upstream
    # We don't care if a client is revoking a different client's tokens
    def authorized?
      token.present?
    end

    def revoke_token
      if token.accessible?
        token.revoke
      end
    end

    def token
      @token ||= AccessToken.authenticate(request.POST['token']) ||
        AccessToken.by_refresh_token(request.POST['token'])
    end

    def strategy
      @strategy ||= server.token_request params[:grant_type]
    end
  end
end
