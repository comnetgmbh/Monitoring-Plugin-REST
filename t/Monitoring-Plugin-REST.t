use strict;
use warnings;

use Test::More tests => 21;
BEGIN { use_ok('Monitoring::Plugin::REST') };

new_ok('Monitoring::Plugin::REST',
    [
        usage => ' ',
    ],
);

# We subclass Monitoring::Plugin::REST in order to hook sending requests
package t::Monitoring::Plugin::REST;

use strict;
use warnings;
use HTTP::Response;
use HTTP::Status qw(:constants :is status_message);
use parent qw/Monitoring::Plugin::REST/;

sub new {
    my $ret = Monitoring::Plugin::REST::new(@_);
    $ret->{requests} = [];
    $ret->{responses} = [];
    return $ret;
}

sub _request {
    my ($this, $request) = @_;
    my $response = shift(@{$this->{responses}}) // HTTP::Response->new(HTTP_OK);

    if ($ENV{MPR_DEBUG}) {
        print(STDERR "Running request:\n----------------\n" . $request->as_string . "----------------\n");
        print(STDERR "Returning:\n----------\n" . $response->as_string . "----------\n\n");
    }

    push(@{$this->{requests}}, $request);

    return $response;
}

sub requests {
    return @{$_[0]->{requests}};
}

sub add_responses {
    push(@{$_[0]->{responses}}, @_[1..$#_]);
}

package main;
use HTTP::Response;
use HTTP::Status qw(:constants :is status_message);
use YAML qw//;
use JSON qw//;

my $auth_response = HTTP::Response->new(
    HTTP_OK,
    'OK',
    [],
    JSON::encode_json({ session_id => '123foobar456' }),
);

my $data_response = HTTP::Response->new(
    HTTP_OK,
    'OK',
    [],
    JSON::encode_json({ sampledata => 'an_entry' }),
);

# Basic plugin usage, no auth
{
    local @ARGV = ('-H', 'http://basic_usage', '-u', 'testuser', '-p', 'secure');
    my $plugin = t::Monitoring::Plugin::REST->new(
        usage => ' ',
    );
    $plugin->getopts;

    $plugin->add_responses($data_response);
    my @data = $plugin->fetch('GET', '/foo');

    my @requests = $plugin->requests;
    is(@requests, 1, 'Simple plugin usage issues exactly one request');
    is($requests[0]->uri->as_string, 'http://basic_usage/foo', 'Simple plugin usage uses the correct URI');
    is_deeply(\@data, [ 200, { sampledata => 'an_entry' } ], 'Simple plugin usage works');
}

# Simple, default authentication
{
    local @ARGV = ('-H', 'http://simple_with_auth', '-u', 'testuser', '-p', 'secure');
    my $plugin = t::Monitoring::Plugin::REST->new(
        usage => ' ',
        authentication => {
            response_map => {
                session_id => [ 'query', 'session_id' ],
            },
        },
    );
    $plugin->getopts;

    $plugin->add_responses($auth_response, $data_response);
    my @data = $plugin->fetch('GET', '/foo');

    my @requests = $plugin->requests;
    is(@requests, 2, 'Default authentication issues exactly two requests');

    # Request
    is($requests[0]->uri->path, '/login', 'Default authentication uses correct endpoint');
    is_deeply(
        { $requests[0]->uri->query_form },
        { user => 'testuser', pass => 'secure' },
        'Default authentication uses credentials'
    );

    # Response
    is_deeply(
        { $requests[1]->uri->query_form },
        { session_id => '123foobar456' },
        'Default authentication supplies session id'
    );
    is_deeply(
        \@data,
        [ 200, { sampledata => 'an_entry' } ],
        'Default authentication works'
    );
}

# Advanced usage
{
    local @ARGV = ('-H', 'http://advanced_usage', '-u', 'advanced', '-p', 'usage');
    my $plugin = t::Monitoring::Plugin::REST->new(
        usage => ' ',
        base_uri => '/foo/@path-session-key@/bar',
        uri_path_parameters => { 'path-session-key' => 'the_key' },
        representation => 'yaml',
        authentication => {
            method => 'POST',
            endpoint => 'authenticate',
            request_map => {
                username => [ 'content', 'my_username' ],
                password => [ 'content', 'data/my_password' ],
            },
            static_query_data => { scope => 'my_scope' },
            static_content_data => { some_data => 'some_other_data' },
            response_map => {
                'data/session-key' => [ 'content', 'my-session-key' ],
                'data/other-data' => [ 'content', 'my-other-data', ],
                'other-session-key' => [ 'path', 'path-session-key' ],
            },
        },
    );
    $plugin->getopts;

    $plugin->add_responses(
        HTTP::Response->new(
            HTTP_OK,
            'OK',
            [],
            YAML::Dump({
                data => {
                    'session-key' => 'the session key',
                    'other-data' => 'some other data',
                },
                'other-session-key' => 'put this in path',
            }),
        ),
        HTTP::Response->new(
            HTTP_OK,
            'OK',
            [],
            YAML::Dump({
                'actual-data' => 'here is some data to check for!',
            }),
        ),
    );

    my @data = $plugin->fetch(
        'PUT',
        '/my_endpoint', 
        query_arguments => {
            additional_query_argument => 'a value',
        },
        content_arguments => {
            additional_content_argument => 'another value',
        },
    );

    my @requests = $plugin->requests;
    is(@requests, 2, 'Advanced usage issued exactly 2 requests');

    # Authentication request
    is($requests[0]->uri->path, '/foo/the_key/bar/authenticate', 'Advanced usage auth uses correct endpoint');
    is($requests[0]->method, 'POST', 'Advanced usage auth uses correct method');
    is_deeply(
        { $requests[0]->uri->query_form },
        { scope => 'my_scope' },
        'Advanced usage auth uses correct query params'
    );
    is_deeply(
        YAML::Load($requests[0]->content),
        {
            my_username => 'advanced',
            data => {
                my_password => 'usage',
            },
            some_data => 'some_other_data'
        },
        'Advanced usage auth uses correct content params'
    );

    # Data request #1
    is($requests[1]->uri->path, '/foo/put%20this%20in%20path/bar/my_endpoint', 'Advanced usage uses correct endpoint');
    is($requests[1]->method, 'PUT', 'Advanced usage uses correct method');
    is_deeply(
        { $requests[1]->uri->query_form },
        {
            additional_query_argument => 'a value',
        },
        'Advanced usage uses correct query params'
    );
    is_deeply(
        YAML::Load($requests[1]->content),
        {
            'my-session-key' => 'the session key',
            'my-other-data' => 'some other data',
            additional_content_argument => 'another value',
        },
        'Advanced usage uses correct content params',
    );

    is_deeply(
        \@data,
        [ 200, { 'actual-data' => 'here is some data to check for!' } ],
        'Advanced usage works',
    );

    # Data request #2
    $plugin->fetch('GET', '/foo');
    @requests = $plugin->requests;
    is(@requests, 3, 'Advanced usage second fetch adds exactly one request');
}
