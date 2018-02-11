%%%----------------------------------------------------------------------
%%%
%%% ejabberd, Copyright (C) 2002-2018   ProcessOne
%%%
%%% This program is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License along
%%% with this program; if not, write to the Free Software Foundation, Inc.,
%%% 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
%%%
%%%----------------------------------------------------------------------

-module(mod_jwt_api).

-author('mremond@process-one.net').

-behaviour(gen_mod).

-export([start/2, stop/1, reload/3, process/2, depends/2, mod_options/1]).

-include("logger.hrl").
-include("ejabberd_http.hrl").

-define(KEY, "MySecretKey").
-define(DEFAULT_API_VERSION, 0).

%% -------------------
%% Module control
%% -------------------

start(_Host, _Opts) ->
    ok.

stop(_Host) ->
    ok.

reload(Host, NewOpts, _OldOpts) ->
    stop(Host),
    start(Host, NewOpts).

depends(_Host, _Opts) ->
    [].

%% ------------------
%% command processing
%% ------------------

%% TODO process login to take username and password and returns jwt token.
%% TODO process other api call, check jwt token in authorization header and then execute API.
%% TODO support default duration + duration that can be overloaded in the token
%% TODO add generation date of token in the token. It will make it possible to
%% blacklist token for a user if generated before a given date. This adds a
%% way to blacklist a full range of token in case token has been leaked.\
%% Note that the date is not enough to protect the service in case secret key has been leaked
%% as the date can be forged by generating new token. In that case, the key need to be replaced.
%% It will invalidate all issues tokens.
%% TODO Content type JSON

%% TODO sliding token ? = provide a new longer token with every API request. This
%% make it possible being stateless
%% TODO Make token id mandatory to enable token blacklisting

%% Unused for now. We expect to token to be generated elsewhere:
%%process([<<"login">>],  #request{method = 'POST', data = <<>>}) ->
%%     %% TODO Parse jid to get username and server
%%    User = "test",
%%    Server = "localhost",
%%    Password = "test2",
%%
%%    case ejabberd_auth:check_password(User, <<>>, Server, Password) of
%%        true ->
%%            {200, [], "Hello"};
%%        false ->
%%            {403, [], "\"Not autorized\""}
%%    end;

process(Call, Request) ->
    #request{headers = Headers} = Request,
    %% Check if we are passing credentials with query
    case proplists:get_value('Authorization', Headers) of
        << "Bearer ", Token/binary >> ->
            process1(Call, Request, Token);
        undefined ->
            %% Missing JWT token (no Bearer authorization header)
            {403, [], "\"Not autorized\""}
    end.

%% Check that token is intended for a known JWT "audience" (= XMPP
%% domain in our case).
process1(Call, Request, Token) ->
    %% First find the right key to use based on payload audience (= domain)
    try jose_jwt:peek_payload(Token) of
        {jose_jwt, Fields} ->
            case maps:get(<<"aud">>, Fields) of
                {badkey,<<"exp">>} ->
                    %% Invalid token: missing audience field
                    {403, [], "\"Not autorized\""};
                Aud ->
                    process2(Call, Request, Token, get_key(Aud))
            end
    catch
        _ ->
            %% Invalid token: cannot extract token payload
            {403, [], "\"Not autorized\""}
    end.

%% Check token signature base on domain key.
process2(_Call, _Request, _Token, undefined) ->
    %% invalid token: token audience unknown
    {403, [], "\"Not autorized\""};
process2(Call, Request, Token, Key) ->
    Jwk = #{<<"kty">> => <<"oct">>, <<"k">> => base64url:encode(Key)},
    try jose_jwt:verify_strict(Jwk, [<<"HS256">>], Token) of
        {true, {jose_jwt, Fields}, Signature} ->
            ?DEBUG("MREMOND verify_strict: ~p - ~p~n", [Fields, Signature]),
            process3(Call, Request, Fields)
    catch
        _ ->
            {403, [], "\"Not autorized\""}
    end.

%% Check expiration date
process3(Call, Request, Fields) ->
    %% Check expiration date
    case maps:get(<<"exp">>, Fields) of
        {badkey,<<"exp">>} ->
            %% No expiry in token => We consider token valid:
            process4(Call, Request, Fields);
        Exp ->
            Now = erlang:system_time(second),
            case Exp > Now of
                true ->
                    process4(Call, Request, Fields);
                false ->
                    %% Token expired
                    {403, [], "\"Not autorized\""}
            end
    end.

%% Check that the user has admin rights
process4(Call, Request, Fields) ->
    case maps:get(<<"roles">>, Fields) of
        {badkey,<<"roles">>} ->
            %% token does not grant admin rights
            {403, [], "\"Not autorized\""};
        Roles ->
            User = maps:get(<<"sub">>, Fields, undefined),
            Host = maps:get(<<"aud">>, Fields, ""),
            IsAdmin = lists:member(<<"admin">>, Roles),
        process5(Call, Request, User, Host, IsAdmin)
    end.

%% TODO support API versioning with accept:
%% Accept : application/vnd.p1.ejabberd-v2+json
%% See: https://blog.octo.com/versioning-de-services-rest/
process5(Call, Request, User, Domain, IsAdmin) ->
    ?DEBUG("~p~n~p~n~p ~p ~p~n", [Call, Request, User, Domain, IsAdmin]),
    Module = get_module(Call),
    Module:handle(Call, Request, User, Domain, IsAdmin).

%% TODO extract key for domain from config file
get_key(<<"localhost">>) ->
    ?KEY;
get_key(_) ->
    undefined.

%% Make sure API modules add their handler to registry on start
get_module([<<"user">>]) ->
    jwt_api_user;
get_module(_) ->
    jwt_api.

mod_options(_) -> [].

%% Test URL with test token:
%% curl -i http://localhost:5280/jwt/ -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJsb2NhbGhvc3QiLCJleHAiOjE1MTg2MjU3MTcsImlhdCI6MTUxODM2NjUxNywiaXNzIjoiRmx1dXhKV1QiLCJzdWIiOiJ0ZXN0Iiwicm9sZXMiOlsiYWRtaW4iXX0.OxZHkz103NH08lSv1a5wvlEzdxK__DpuZfBYuRS87Vw"
