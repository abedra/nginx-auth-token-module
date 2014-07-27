require 'sinatra'

get '/app' do
  "Hello #{request.env['HTTP_X_USER_ID']}"
end
