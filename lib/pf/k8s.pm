package pf::k8s;

use strict;
use warnings;

use UNIVERSAL::require;
use JSON::MaybeXS qw(encode_json decode_json);
use pf::constants qw($TRUE $FALSE);
use pf::log;
use URI;
use LWP::UserAgent;
use Moo;

has ca_file => (is => 'rw');
has token => (is => 'rw');
has proto => (is => 'rw', default => 'https');
has host => (is => 'rw');
has port => (is => 'rw', default => 443);
has namespace => (is => 'rw', default => 'default');
has ua => (is => 'rw');

sub get_ua {
    my ($self) = @_;
    
    unless($self->ua) {
        my $ua = LWP::UserAgent->new();
        $ua->default_header("Authorization" => "Bearer ".$self->token);
        $ua->ssl_opts(SSL_ca_file => $self->ca_file);
        $self->ua($ua);
    }

    return $self->ua;
}

sub build_uri {
    my ($self, $path, $params) = @_;
    my $u = URI->new($self->proto."://".$self->host.":".$self->port.$path);
    if($params) {
        $u->query_form($params);
    }
    return $u->as_string;
}

sub execute_request {
    my ($self, $req) = @_;
    my $res = $self->get_ua->request($req);
    if($res->is_success) {
        return ($TRUE, decode_json($res->decoded_content));
    }
    elsif($res->code == $STATUS::FORBIDDEN || $res->code == $STATUS::UNAUTHORIZED){
        my $msg = "Cannot authenticate/authorize against the K8S master API. Please check your configuration.";
        get_logger->error($msg);
        return (undef, $msg, $res);
    }
    else {
        my $msg = "Error while communicating with K8S master API: ".$res->status_line;
        get_logger->error($msg);
        return (undef, $msg, $res);
    }
}

sub env_build {
    my ($proto) = @_;

    my $k8s = pf::k8s->new();
    $k8s->ca_file($ENV{K8S_MASTER_CA_FILE});
    if($ENV{K8S_MASTER_TOKEN}) {
        $k8s->token($ENV{K8S_MASTER_TOKEN});
    }
    elsif($ENV{K8S_MASTER_TOKEN_PATH}) {
        $k8s->token(read_file($ENV{K8S_MASTER_TOKEN_PATH}));
    }

    if($ENV{K8S_NAMESPACE}) {
        $k8s->namespace($ENV{K8S_NAMESPACE});
    }
    elsif($ENV{K8S_NAMESPACE_PATH}) {
        $k8s->namespace(read_file($ENV{K8S_NAMESPACE_PATH}));
    }

    if($ENV{K8S_MASTER_URI}) {
        my $u = URI->new($ENV{K8S_MASTER_URI});
        $k8s->proto($u->scheme);
        $k8s->host($u->host);
        $k8s->port($u->port);
    } else {
        die "Missing K8S_MASTER_URI environment value";
    }

    return $k8s;
}

sub api_module {
    my ($self, $module) = @_;

    if ( !( eval "$module->require()" ) ) {
        die( "Can not load K8S API module $module " . "Read the following message for details: $@" );
    }

    return $module->new(
        %$self,
    );
}

1;
