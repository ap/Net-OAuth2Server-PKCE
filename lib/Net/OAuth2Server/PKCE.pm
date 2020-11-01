use strict; use warnings;

package Net::OAuth2Server::PKCE;

our $VERSION = '0.001';

use Digest::SHA ();

sub VALID_CHALLENGE () { qr/\A   [-_A-Za-z0-9]{43}     \z/x }
sub VALID_VERIFIER  () { qr/\A [-._~A-Za-z0-9]{43,128} \z/x }

our %transform = (
	plain => sub () { $_[0] },
	S256  => sub () { my $v = &Digest::SHA::sha256_base64; $v =~ y[+/][-_]; $v },
);

package Net::OAuth2Server::Request::Authorization::Role::PKCE;

our $VERSION = '0.001';

use Role::Tiny;
use Class::Method::Modifiers 'fresh';

sub fresh__get_pkce_challenge {
	my $self = shift;
	$self->ensure_required( qw( code_challenge code_challenge_method ) ) or return;
	my ( $challenge, $method ) = $self->params( qw( code_challenge code_challenge_method ) );
	$self->set_error_invalid_request( "unsupported code_challenge_method: $method" ), return
		if not exists $transform{ $method };
	$self->set_error_invalid_request( 'malformed code_challenge value ' . $challenge ), return
		if $challenge !~ Net::OAuth2Server::PKCE::VALID_CHALLENGE;
	( $challenge, $method );
}
fresh get_pkce_challenge => \&fresh__get_pkce_challenge;
undef *fresh__get_pkce_challenge;

sub fresh__get_pkce_token {
	my ( $self, $secret ) = ( shift, @_ );
	my ( $challenge, $method ) = $self->get_pkce_challenge or return;
	( my $hmac = Digest::SHA::hmac_sha256_base64( "$method $challenge", $secret ) ) =~ y[+/][-_];
	"$hmac $method";
}
fresh get_pkce_token => \&fresh__get_pkce_token;
undef *fresh__get_pkce_token;

package Net::OAuth2Server::Request::Token::AuthorizationCode::Role::PKCE;

our $VERSION = '0.001';

use Role::Tiny;
use Class::Method::Modifiers 'fresh';
use Carp ();

sub no_secret_required { my $orig = shift; grep 'client_secret' ne $_, shift->$orig( @_ ) };
around required_parameters => \&no_secret_required;

sub fresh__get_pkce_challenge {
	my ( $self, $method ) = ( shift, @_ );
	my $t = $transform{ $method }
		or Carp::croak( "bad code_challenge_method: $method" );
	$self->ensure_required( 'code_verifier' ) or return;
	my $verifier = $self->param( 'code_verifier' );
	$self->set_error_invalid_request( 'malformed code_verifier value' ), return
		if $verifier !~ Net::OAuth2Server::PKCE::VALID_VERIFIER;
	$t->( $verifier );
}
fresh get_pkce_challenge => \&fresh__get_pkce_challenge;
undef *fresh__get_pkce_challenge;

sub fresh__ensure_pkce_token {
	my ( $self, $secret, $token ) = ( shift, @_ );
	my ( $orig_hmac, $method ) = split / /, $token, 2;
	my ( $challenge ) = $self->get_pkce_challenge( $method ) or return !1;
	( my $hmac = Digest::SHA::hmac_sha256_base64( "$method $challenge", $secret ) ) =~ y[+/][-_];
	( my $ok = $hmac eq $orig_hmac ) or $self->set_error_invalid_client;
	$ok;
}
fresh ensure_pkce_token => \&fresh__ensure_pkce_token;
undef *fresh__ensure_pkce_token;

1;

__END__

=pod

=encoding UTF-8

=head1 NAME

Net::OAuth2Server::PKCE - A PKCE extension for Net::OAuth2Server

=head1 DISCLAIMER

B<I cannot promise that the API is fully stable yet.>
For that reason, no documentation is provided.

=head1 DESCRIPTION

A simple implementation of PKCE.

=head1 SEE ALSO

=over 2

=item *

L<RFCE<nbsp>7636, I<Proof Key for Code Exchange by OAuth Public Clients>|https://tools.ietf.org/html/rfc7636>

=item *

L<Internet-Draft, S<Parecki et al>, I<OAuth 2.0 for Browser-Based Apps>|https://tools.ietf.org/html/draft-parecki-oauth-browser-based-apps>

=back

=cut
