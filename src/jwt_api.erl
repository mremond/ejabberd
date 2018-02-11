-module(jwt_api).

-export([handle/5]).

-include("logger.hrl").

%% Default endpoint
handle(_Call, _Request, _User, _Domain, _Role) ->
    ?DEBUG("In default module~n", []),
    {200, [], "Hello\n"}.
