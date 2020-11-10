use strict; use warnings;
use Test::More tests => 4;
use Net::OAuth2Server::PKCE;
use Net::OAuth2Server::Request::Token::AuthorizationCode;
use Role::Tiny;

Role::Tiny->apply_roles_to_package( glob 'Net::OAuth2Server::Request::Token::AuthorizationCode{,::Role::PKCE}' );

my ( $v, $ch ) = (
	'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
	'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
);

like $v,  Net::OAuth2Server::PKCE::VALID_VERIFIER,  'valid verifier';
like $ch, Net::OAuth2Server::PKCE::VALID_CHALLENGE, 'valid challenge';
is +( Net::OAuth2Server::Request::Token::AuthorizationCode->from( GET => 'code_verifier=' . $v )->get_pkce_challenge( 'plain' ) )[0], $v, 'code_challenge_method plain';
is +( Net::OAuth2Server::Request::Token::AuthorizationCode->from( GET => 'code_verifier=' . $v )->get_pkce_challenge( 'S256' ) )[0], $ch, 'code_challenge_method S256 (example from RFC 7636 Appendix B)';
