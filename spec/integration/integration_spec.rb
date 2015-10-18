require 'spec_helper'

describe "Integration Specs" do

  before do
    @redis = Redis.new
    @redis.flushdb
  end

  after  { @redis.flushdb }

  describe "Use cases" do
    it "Redirects when no auth token is present" do
      http = Curl.get("http://127.0.0.1:8888") do |http|
        http.headers['Cookie'] = ""
      end

      expect(http.response_code).to eq(302)
      expect(http.redirect_url).to eq("http://google.com")
    end

    it "Redirects when the auth token is invalid" do
      @redis.set("test", "sucess")

      http = Curl.get("http://127.0.0.1:8888") do |http|
        http.headers['Cookie'] = "auth_token=invalid"
      end

      expect(http.response_code).to eq(302)
    end

    it "Allows the request when the auth token is valid" do
      @redis.set("test", "sucess")

      http = Curl.get("http://127.0.0.1:8888") do |http|
        http.headers['Cookie'] = "auth_token=test"
      end

      expect(http.response_code).to eq(200)
    end

    it "handles user ids longer than 7 characters" do
      @redis.set("f0f70003-f368-4266-a448-c45a96b8fc13", "user-longer-than-seven-characters")

      http = Curl.get("http://127.0.0.1:8888") do |http|
        http.headers['Cookie'] = "auth_token=f0f70003-f368-4266-a448-c45a96b8fc13"
      end

      expect(http.response_code).to eq(200)
    end

    it "respects the location section redirect directive" do
      http = Curl.get("http://127.0.0.1:8888/location")
      expect(http.response_code).to eq(302)
      expect(http.redirect_url).to eq("http://google.com/location")
    end

    it "respects the server section redirect directive" do
      http = Curl.get("http://127.0.0.1:8889/")
      expect(http.response_code).to eq(302)
      expect(http.redirect_url).to eq("http://google.com/server")
    end

    it "properly locates the authentication token in a header" do
      @redis.set("test", "sucess")

      http = Curl.get("http://127.0.0.1:8889") do |http|
        http.headers['X-Authorization'] = "test"
      end

      expect(http.response_code).to eq(200)
    end
  end
end
