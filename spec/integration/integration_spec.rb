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
  end
end
