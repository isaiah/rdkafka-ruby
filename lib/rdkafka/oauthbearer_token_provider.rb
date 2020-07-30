require 'oauth2'

class OauthbearerTokenProvider
  TOKEN_GRACE_PERIOD = 5 # seconds

  # Initializes a new client with specified OAuth parameters and a debug logger.
  def initialize(client_id, client_secret, token_url, logger = Logger.new($stdout))
    @client_id = client_id
    @client = OAuth2::Client.new(client_id, client_secret, token_url: token_url)
    @refresh_monitor = Monitor.new
    @logger = logger
  end

  # Returns an OAuth token valid for TOKEN_GRACE_PERIOD more seconds. Thread-safe.
  def token
    @refresh_monitor.synchronize { oauth_token.token }
  end

  def principal
    @client_id
  end

  def expires_at
    oauth_token.expires_at
  end

  private

  def oauth_token
    return @oauth_token if oauth_token_available?

    @logger.debug("Obtaining new OAuth token")
    @oauth_token = @client.client_credentials.get_token
  end

  def oauth_token_available?
    @oauth_token && remaining_token_ttl > TOKEN_GRACE_PERIOD
  end

  def remaining_token_ttl
    return 0 unless @oauth_token
    Time.at(expires_at) - Time.now
  end
end
