require 'sinatra'

get '/' do
  "Hello #{request.env['HTTP_X_USER_ID']}"
end
