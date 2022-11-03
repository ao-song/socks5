%% For supervisors
-define(MAX_RESTART,   5).
-define(MAX_TIME,      60).
-define(DEFAULT_PORT,  1080).
-define(TIMEOUT,       60000).
-define(CHILD(I, Type, Arg),
        {I, {I, start_link, Arg}, temporary, infinity, Type, [I]}).


%% Socks5 definitions
-define(SOCKS_VERSION,                16#05).
-define(RSV,                          16#00).
-define(NMETHODS,                     1).
%% Authentication methods
%% X'03'~X'7F' IANA assigned
%% X'80'~X'FE' reserved for private methods
-define(NO_AUTHENTICATION_REQUIRED,   16#00).
-define(GSSAPI,                       16#01).
-define(USERNAME_PASSWORD,            16#02).
-define(NO_ACCEPTABLE_METHODS,        16#ff).
-define(CONNECT,                      16#01).
-define(BIND,                         16#02).
-define(UDP_ASSOCIATE,                16#03).
-define(ATYP_IPV4,                    16#01).
-define(DOMAINNAME,                   16#03).
-define(ATYP_IPV6,                    16#04).
-define(SUCCEEDED,                    16#00).
-define(GENERAL_SOCKS_SERVER_FAILURE, 16#01).
-define(CONNECTION_NOT_ALLOWED,       16#02).
-define(NETWORK_UNREACHABLE,          16#03).
-define(HOST_UNREACHABLE,             16#04).
-define(CONNECTION_REFUSED,           16#05).
-define(TTL_EXPIRED,                  16#06).
-define(CMD_NOT_SUPPORTED,            16#07).
-define(ATYP_NOT_SUPPORTED,           16#08).
