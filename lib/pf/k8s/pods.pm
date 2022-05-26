package pf::k8s::pods;

use Moo;

extends "pf::k8s";

sub list {
    my ($self, $params) = @_;
    return $self->execute_request(HTTP::Request::Common::GET($self->build_uri("/api/v1/namespaces/".$self->namespace."/pods", $params)));
}

sub delete {
    my ($self, $pod_name) = @_;
    return $self->execute_request(HTTP::Request::Common::DELETE($self->build_uri("/api/v1/namespaces/".$self->namespace."/pods/$pod_name")));
}

sub run_all_pods {
    my ($self, $list_params, $container_name, $on_ready, $on_not_ready) = @_;

    my ($success, $res) = $self->list($list_params);

    return ($success, $res) unless($success);

    for my $pod (@{$res->{items}}) {
        for my $containerStatus (@{$pod->{status}->{containerStatuses}}) {
            if($containerStatus->{name} eq $container_name) {
                if($containerStatus->{ready}) {
                    $on_ready->($pod);
                }
                else {
                    $on_not_ready->($pod);
                }
            }
        }
    }
}

1;
