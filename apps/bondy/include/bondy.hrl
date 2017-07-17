%% =============================================================================
%%  bondy.hrl -
%% 
%%  Copyright (c) 2016-2017 Ngineo Limited t/a Leapsight. All rights reserved.
%% 
%%  Licensed under the Apache License, Version 2.0 (the "License");
%%  you may not use this file except in compliance with the License.
%%  You may obtain a copy of the License at
%% 
%%     http://www.apache.org/licenses/LICENSE-2.0
%% 
%%  Unless required by applicable law or agreed to in writing, software
%%  distributed under the License is distributed on an "AS IS" BASIS,
%%  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%  See the License for the specific language governing permissions and
%%  limitations under the License.
%% =============================================================================



-define(BONDY_VERSION_STRING, <<"LEAPSIGHT-BONDY-0.5.2">>).
-define(BONDY_REALM_URI, <<"com.leapsight.bondy">>).

-define(BONDY_PEER_CALL, '$bondy_call').
-define(BONDY_PEER_ACK, '$bondy_ack').


%% =============================================================================
%% FEATURES
%% =============================================================================




-define(DEALER_FEATURES, #{
    progressive_call_results => false,
    progressive_calls => false,
    call_timeout => true,
    call_canceling => false,
    caller_identification => false,
    call_trustlevels => false,
    registration_meta_api => false,
    registration_revocation => false,
    session_meta_api => false,
    pattern_based_registration => true,
    procedure_reflection => false,
    shared_registration => true,
    sharded_registration => false
}).

-define(CALLEE_FEATURES, #{
    progressive_call_results => false,
    progressive_calls => false,
    call_timeout => true,
    call_canceling => false,
    caller_identification => false,
    call_trustlevels => false,
    registration_revocation => false,
    session_meta_api => false,
    pattern_based_registration => true,
    shared_registration => true,
    sharded_registration => false
}).

-define(CALLER_FEATURES, #{
    progressive_call_results => false,
    progressive_calls => false,
    call_timeout => false,
    call_canceling => false,
    caller_identification => false
}).

-define(BROKER_FEATURES, #{
    event_history => false,
    pattern_based_subscription => true,
    publication_trustlevels => false,
    publisher_exclusion => false,
    publisher_identification => false,
    session_meta_api => false,
    sharded_subscription => false,
    subscriber_blackwhite_listing => false,
    subscription_meta_api => false,
    topic_reflection => false
}).

-define(SUBSCRIBER_FEATURES, #{
    event_history => false,
    pattern_based_subscription => true,
    publication_trustlevels => false,
    publisher_identification => false,
    sharded_subscription => false
}).

-define(PUBLISHER_FEATURES, #{
    publisher_exclusion => false,
    publisher_identification => false,
    subscriber_blackwhite_listing => false
}).





%% =============================================================================
%% META EVENTS & PROCEDURES
%% =============================================================================

% USER
-define(BONDY_USER_ADD, <<"com.leapsight.bondy.security.add_user">>).
-define(BONDY_USER_UPDATE, <<"com.leapsight.bondy.security.update_user">>).
-define(BONDY_USER_LOOKUP, <<"com.leapsight.bondy.security.find_user">>).
-define(BONDY_USER_DELETE, <<"com.leapsight.bondy.security.delete_user">>).
-define(BONDY_USER_LIST, <<"com.leapsight.bondy.security.list_users">>).

-define(BONDY_USER_CHANGE_PASSWORD, <<"com.leapsight.bondy.security.users.change_password">>).

-define(BONDY_USER_ON_ADD, <<"com.leapsight.bondy.security.user_added">>).
-define(BONDY_USER_ON_DELETE, <<"com.leapsight.bondy.security.user_deleted">>).
-define(BONDY_USER_ON_UPDATE, <<"com.leapsight.bondy.security.user_updated">>).


% GROUP
-define(BONDY_GROUP_ADD, <<"com.leapsight.bondy.security.add_group">>).
-define(BONDY_GROUP_UPDATE, <<"com.leapsight.bondy.security.update_group">>).
-define(BONDY_GROUP_LOOKUP, <<"com.leapsight.bondy.security.find_group">>).
-define(BONDY_GROUP_DELETE, <<"com.leapsight.bondy.security.delete_group">>).
-define(BONDY_GROUP_LIST, <<"com.leapsight.bondy.security.list_groups">>).

-define(BONDY_GROUP_ON_ADD, <<"com.leapsight.bondy.security.group_added">>).
-define(BONDY_GROUP_ON_DELETE, <<"com.leapsight.bondy.security.group_deleted">>).
-define(BONDY_GROUP_ON_UPDATE, <<"com.leapsight.bondy.security.group_updated">>).


% SOURCE
-define(BONDY_SOURCE_ADD, <<"com.leapsight.bondy.security.add_source">>).
-define(BONDY_SOURCE_DELETE, <<"com.leapsight.bondy.security.delete_source">>).
-define(BONDY_SOURCE_LOOKUP, <<"com.leapsight.bondy.security.find_source">>).
-define(BONDY_SOURCE_LIST, <<"com.leapsight.bondy.security.list_sources">>).

-define(BONDY_SOURCE_ON_ADD, <<"com.leapsight.bondy.security.source_added">>).
-define(BONDY_SOURCE_ON_DELETE, <<"com.leapsight.bondy.security.source_deleted">>).




%% =============================================================================
%% API GATEWAY
%% =============================================================================



-define(BONDY_GATEWAY_CLIENT_CHANGE_PASSWORD,
    <<"com.leapsight.bondy.api_gateway.change_password">>).

-define(BONDY_GATEWAY_CLIENT_ADD,
    <<"com.leapsight.bondy.api_gateway.add_client">>).
-define(BONDY_GATEWAY_CLIENT_DELETE,
    <<"com.leapsight.bondy.api_gateway.delete_client">>).
-define(BONDY_GATEWAY_CLIENT_LIST,
    <<"com.leapsight.bondy.api_gateway.list_clients">>).
-define(BONDY_GATEWAY_CLIENT_LOOKUP,
    <<"com.leapsight.bondy.api_gateway.get_client">>).
-define(BONDY_GATEWAY_CLIENT_UPDATE,
    <<"com.leapsight.bondy.api_gateway.update_client">>).

-define(BONDY_GATEWAY_CLIENT_ON_ADD,
    <<"com.leapsight.bondy.api_gateway.client_added">>).
-define(BONDY_GATEWAY_CLIENT_ON_DELETE,
    <<"com.leapsight.bondy.api_gateway.clients.client_deleted">>).
-define(BONDY_GATEWAY_CLIENT_ON_UPDATE,
    <<"com.leapsight.bondy.api_gateway.clients.client_updated">>).


-define(BONDY_GATEWAY_RESOURCE_OWNER_ADD,
    <<"com.leapsight.bondy.api_gateway.add_resource_owner">>).
-define(BONDY_GATEWAY_RESOURCE_OWNER_DELETE,
    <<"com.leapsight.bondy.api_gateway.delete_resource_owner">>).
-define(BONDY_GATEWAY_RESOURCE_OWNER_LIST,
    <<"com.leapsight.bondy.api_gateway.list_resource_owners">>).
-define(BONDY_GATEWAY_RESOURCE_OWNER_LOOKUP,
    <<"com.leapsight.bondy.api_gateway.get_resource_owner">>).
-define(BONDY_GATEWAY_RESOURCE_OWNER_UPDATE,
    <<"com.leapsight.bondy.api_gateway.update_resource_owner">>).

-define(BONDY_GATEWAY_RESOURCE_OWNER_ON_ADD,
    <<"com.leapsight.bondy.api_gateway.resource_owner_added">>).
-define(BONDY_GATEWAY_RESOURCE_OWNER_ON_DELETE,
    <<"com.leapsight.bondy.api_gateway.resource_owner_deleted">>).
-define(BONDY_GATEWAY_RESOURCE_OWNER_ON_UPDATE,
    <<"com.leapsight.bondy.api_gateway.resource_owner_updated">>).


-define(BONDY_GATEWAY_LOAD_API_SPEC,
    <<"com.leapsight.bondy.api_gateway.load_api_spec">>).


%% =============================================================================
%% GENERAL
%% =============================================================================



-define(BONDY_ERROR_NOT_IN_SESSION, <<"com.leapsight.bondy.error.not_in_session">>).
-define(BONDY_SESSION_ALREADY_EXISTS, <<"com.leapsight.bondy.error.session_already_exists">>).

-define(BONDY_ERROR_TIMEOUT, <<"com.leapsight.bondy.error.timeout">>).

-type peer_id() :: {integer(), pid()}.





%% =============================================================================
%% UTILS
%% =============================================================================

-define(EOT, '$end_of_table').
-define(CHARS2BIN(Chars), unicode:characters_to_binary(Chars, utf8, utf8)).
-define(CHARS2LIST(Chars), unicode:characters_to_list(Chars, utf8)).