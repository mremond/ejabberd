-module(jwt_api_user).

-author('mremond@process-one.net').

-export([handle/5]).

-include("logger.hrl").

%% Default endpoint
handle(_Call, _Request, _User, _Domain, _Role) ->
    ?DEBUG("In User module~n", []),
    {200, [], "Hello\n"}.
