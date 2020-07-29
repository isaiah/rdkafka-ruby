require "spec_helper"

describe Rdkafka::Config do
  context "logger" do
    it "should have a default logger" do
      expect(Rdkafka::Config.logger).to be_a Logger
    end

    it "should set the logger" do
      logger = Logger.new(STDOUT)
      expect(Rdkafka::Config.logger).not_to eq logger
      Rdkafka::Config.logger = logger
      expect(Rdkafka::Config.logger).to eq logger
    end

    it "should not accept a nil logger" do
      expect {
        Rdkafka::Config.logger = nil
      }.to raise_error(Rdkafka::Config::NoLoggerError)
    end
  end

  context "statistics callback" do
    it "should set the callback" do
      expect {
        Rdkafka::Config.statistics_callback = lambda do |stats|
          puts stats
        end
      }.not_to raise_error
      expect(Rdkafka::Config.statistics_callback).to be_a Proc
    end

    it "should not accept a callback that's not a proc" do
      expect {
        Rdkafka::Config.statistics_callback = 'a string'
      }.to raise_error(TypeError)
    end
  end

  context "oauthbearer token provider" do
    let(:token_provider) do
      double(:OauthbearerTokenProvider, principal: "test", token: "abcd", expires_at: Time.now.to_i + 3_600_000)
      #OauthbearerTokenProvider.new('user', 'password', 'https://openid.net')
    end

    let(:config) { Rdkafka::Config.new }

    it "should set oauthbearer token refresh callback" do
      config.token_provider = OauthbearerTokenProvider.new('user', 'password', 'https://openid.net')
    end

    it "should set authentication to OAUTHBEARER when given a token provider"

    it "should set oauth token when create a new consumer" do
      #expect(:token_provider).to receive(:token).and_return("abcd")
      config.token_provider = token_provider
      config.consumer
    end
  end

  context "configuration" do
    it "should store configuration" do
      config = Rdkafka::Config.new
      config[:"key"] = 'value'
      expect(config[:"key"]).to eq 'value'
    end

    it "should use default configuration" do
      config = Rdkafka::Config.new
      expect(config[:"api.version.request"]).to eq true
    end

    it "should create a consumer with valid config" do
      consumer = rdkafka_config.consumer
      expect(consumer).to be_a Rdkafka::Consumer
      consumer.close
    end

    it "should raise an error when creating a consumer with invalid config" do
      config = Rdkafka::Config.new('invalid.key' => 'value')
      expect {
        config.consumer
      }.to raise_error(Rdkafka::Config::ConfigError, "No such configuration property: \"invalid.key\"")
    end

    it "should raise an error when creating a consumer with a nil key in the config" do
      config = Rdkafka::Config.new(nil => 'value')
      expect {
        config.consumer
      }.to raise_error(Rdkafka::Config::ConfigError, "No such configuration property: \"\"")
    end

    it "should treat a nil value as blank" do
      config = Rdkafka::Config.new('security.protocol' => nil)
      expect {
        config.consumer
        config.producer
      }.to raise_error(Rdkafka::Config::ConfigError, "Configuration property \"security.protocol\" cannot be set to empty value")
    end

    it "should create a producer with valid config" do
      producer = rdkafka_config.producer
      expect(producer).to be_a Rdkafka::Producer
      producer.close
    end

    it "should raise an error when creating a producer with invalid config" do
      config = Rdkafka::Config.new('invalid.key' => 'value')
      expect {
        config.producer
      }.to raise_error(Rdkafka::Config::ConfigError, "No such configuration property: \"invalid.key\"")
    end

    it "should raise an error when client creation fails for a consumer" do
      config = Rdkafka::Config.new(
        "security.protocol" => "SSL",
        "ssl.ca.location" => "/nonsense"
      )
      expect {
        config.consumer
      }.to raise_error(Rdkafka::Config::ClientCreationError, /ssl.ca.location failed(.*)/)
    end

    it "should raise an error when client creation fails for a producer" do
      config = Rdkafka::Config.new(
        "security.protocol" => "SSL",
        "ssl.ca.location" => "/nonsense"
      )
      expect {
        config.producer
      }.to raise_error(Rdkafka::Config::ClientCreationError, /ssl.ca.location failed(.*)/)
    end
  end
end
