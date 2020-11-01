use strict; use warnings;
use Test::More tests => 4;
use Net::OAuth2Server::PKCE;

my ( $v, $ch ) = (
	'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
	'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
);

like $v,  Net::OAuth2Server::PKCE::VALID_VERIFIER,  'valid verifier';
like $ch, Net::OAuth2Server::PKCE::VALID_CHALLENGE, 'valid challenge';
is $Net::OAuth2Server::PKCE::transform{'plain'}->( $v ), $v,  'code_challenge_method plain';
is $Net::OAuth2Server::PKCE::transform{'S256'} ->( $v ), $ch, 'code_challenge_method S256 (example from RFC 7636 Appendix B)';
