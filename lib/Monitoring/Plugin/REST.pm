package Monitoring::Plugin::REST;

use 5.010000;
use strict;
use warnings;
use Carp;
use LWP::UserAgent;
use HTTP::Status qw(:constants :is status_message);
use YAML qw//;
use JSON qw//;
use parent qw/Monitoring::Plugin Class::Accessor/;

my @ATTRIBUTES = qw/base_uri uri_path_parameters representation authentication/;
__PACKAGE__->mk_accessors(@ATTRIBUTES);

our $VERSION = '1.10';

#
# Internal helper methods
#

# Prints a message to STDERR if MPR_DEBUG is set
sub _debug($$) {
    my ($this, $message) = @_;

    print(STDERR "[DEBUG] $message\n") if $ENV{MPR_DEBUG};
}

# Constructs an URI object according to the object state and path + arguments given
# Also performs URI expansion
sub _mkuri {
    my ($this, $path, %args) = @_;

    # Build URI
    my $uri_string = $this->opts->get('host') . '/' . $this->{base_uri} . '/' . $path;
    $uri_string =~ s#(\w)/+#$1/#g;

    # Expand URI
    while (my ($key, $value) = each(%{$this->{auth_path}})) {
        $uri_string =~ s/@\Q$key\E@/$value/g;
    }

    my $uri = URI->new($uri_string);
    $uri->query_form(\%args);

    return $uri->as_string;
}

# Takes HTTP::Request objects and actually performs the request described there.
# NOTE:  Always use this method to perform requests, as this is overriden in our
# tests in order to simulate HTTP connections.
sub _request($$) {
    my ($this, $request) = @_;

    $this->_debug(
        "Running request:\n" . YAML::Dump(
        {
            method  => $request->method,
            uri     => $request->uri->as_string,
            headers => { $request->headers->flatten, },
            content => $request->content,
        }),
    );
    
    my $response = $this->ua->request($request);
    
    $this->_debug(
        "Response:\n" . YAML::Dump(
        {
            code    => $response->code,
            headers => { $response->headers->flatten, },
            content => $response->content,
        }),
    );
    
    return $response;
}

# Returns a true value if we're authenticated, a false value if not
sub _authenticated($) {
    my $this = shift;

    return 1 if keys(%{$this->{auth_query}});
    return 1 if keys(%{$this->{auth_content}});
    return 1 if $this->ua->cookie_jar->as_string;
    return 0;
}

# Takes a reference and returns a string containing the serialized equivalent
sub _serialize {
    my ($this, $data) = @_;

    my $ret;
    if ($this->representation eq 'yaml') {
        $ret = YAML::Dump($data);
    }
    elsif ($this->representation eq 'json') {
        $ret = JSON::encode_json($data);
    }
    else {
        confess('Unknown data representation: ' . $this->representation);
    }

    return $ret;
}

# Takes a string and returns a reference containing the deserialized equivalent
# Throws an exception if the string does not contain valid data
sub _deserialize {
    my ($this, $data) = @_;

    my $ret;
    my $e;
    if ($this->representation eq 'yaml') {
        $ret = eval {
            YAML::Load($data);
        };
        $e = $@;
    }
    elsif ($this->representation eq 'json') {
        $ret = eval {
            JSON::decode_json($data);
        };
        $e = $@;
    }
    else {
        confess('Unknown data representation: ' . $this->representation);
    }

    confess("Can't decode response: $e") if $e;
    return $ret;
}

# Nested hash getter
sub _nested_hash_get($$$) {
    my ($this, $hashref, $path) = @_;

    my $e = $hashref;
    my @path = split('/', $path);

    while (@path) {
        $e = $e->{shift(@path)};
    }

    return $e;
}

# Nested hash setter
sub _nested_hash_set($$$$) {
    my ($this, $hashref, $path, $value) = @_;

    my $e = $hashref;
    my @path = split('/', $path);

    while (@path) {
        my $k = shift(@path);

        if (@path) {
            $e->{$k} //= {};
            $e = $e->{$k};
        }
        else {
            $e->{$k} = $value;
        }
    }
}


#
# Accessors
#

sub ua($) {
    my $this = shift;

    unless (defined($this->{ua})) {
        my %args;
        if ($this->opts->get('insecure')) {
            $args{ssl_opts} = { verify_hostname => 0 };
        }

        my $ua = LWP::UserAgent->new(%args);
        $ua->cookie_jar({});

        $this->{ua} = $ua;
    }

    return $this->{ua};
}

#
# Public functions and methods
#

# Object constructor
sub new {
    my ($class, %args) = @_;

    # Prepare arguments
    my %plugin_args = %args;
    delete($plugin_args{$_}) for (@ATTRIBUTES);

    # Construct object
    my $ret = Monitoring::Plugin::new($class, \%plugin_args);

    # Set up attributes
    $ret->{base_uri} = $args{base_uri} // '/';
    $ret->{representation} = $args{representation} // 'json';
    $ret->{authentication} = $args{authentication};
    $ret->{auth_path} = $args{uri_path_parameters} // {};
    $ret->{auth_header} = {};
    $ret->{auth_query} = {};
    $ret->{auth_content} = {};

    # Default command line arguments
    $ret->add_arg(
        spec => 'host|H=s',
        help => "-H, --host=HOST\n   The host to query",
    );
    $ret->add_arg(
        spec => 'username|u=s',
        help => "-u, --username=USERNAME\n   Username to use while authenticating",
    );
    $ret->add_arg(
        spec => 'password|p=s',
        help => "-p, --password=PASSWORD\n   Password to use while authenticating",
    );
    $ret->add_arg(
        spec => 'insecure|i',
        help => "-i, --insecure\n    Do not verify TLS certificate hostname",
    );

    return $ret;
}

# Run authentication
sub authenticate {
    my $this = shift;

    # Do we need to authenticate?
    return unless defined $this->{authentication};

    # We'll need login credentials
    confess("Authentication requires username and password") unless defined $this->opts->get('username') and defined $this->opts->get('password');

    # Prepare
    my %authentication = (
        # authentication default values
        method => 'GET',
        endpoint => '/login',
        request_map => {
            username => [ 'query', 'user' ],
            password => [ 'query', 'pass' ],
        },
        static_query_data => {},
        static_content_data => {},
        response_map => {
        },

        # Developer-supplied values
        %{$this->{authentication}},
    );

    # Valid method?
    confess "Invalid method: $authentication{method}" unless $authentication{method} =~ /^(GET|POST|PUT)$/;

    # Prepare request
    my %request = (
        query => $authentication{static_query_data},
        content => $authentication{static_content_data},
    );

    # Perform request mapping to uri query parameters and request content
    for (qw/username password/) {
        my $mapping = $authentication{request_map}->{$_};
        next unless defined $mapping;

        my ($type, $key) = @{$mapping};
        confess('Invalid request mapping: ' . $type) unless $type =~ /^(query|content)$/;
        confess('content mapping while using GET') if $type eq 'content' and $authentication{method} eq 'GET';

        $this->_nested_hash_set($request{$type}, $key, $this->opts->get($_));
    }

    # Build request
    my $request = HTTP::Request->new(
        $authentication{method},
        $this->_mkuri($authentication{endpoint}, %{$request{query}}),
        [],
        $this->_serialize($request{content}),
    );

    # Fetch response
    my $http_response = $this->_request($request);
    confess('Authentication failed: ' . $http_response->as_string) unless $http_response->code == HTTP_OK;
    my $response = $this->_deserialize($http_response->content);

    # Apply result, saving values in auth_(query|path|content) as described in
    # %authentication
    while (my ($response_key, $mapping) = each(%{$authentication{response_map}})) {
        my ($type, $key) = @{$mapping};

        # Verify mapping entry
        confess('Invalid response mapping: ' . $type) unless $type =~ /^(query|path|content|header)$/;

        # Did we get that entry?
        confess("Authentication failed: We did not receive $response_key") unless defined $this->_nested_hash_get($response, $response_key);

        # Handled nested hash paths correctly
        $this->_nested_hash_set($this->{'auth_' . $type}, $key, $this->_nested_hash_get($response, $response_key));
    }
}

sub fetch {
    my ($this, $method, $path, %args) = @_;

    # Default values for arguments
    my $header_args = $args{header_arguments} // {};
    my $query_args = $args{query_arguments} // {};
    my $content_args = $args{content_arguments} // {};

    # Check arguments
    confess('No host given') unless defined $this->opts->get('host');
    confess('No method given') unless defined $method;
    confess('content_arguments given while using GET') if $method =~ tr/a-z/A-Z/r eq 'GET' and @{[keys(%{$content_args})]} > 0;
    confess('No path given') unless defined $path;

    # Run authentication
    $this->authenticate unless $this->_authenticated;

    # Prepare request
    my $request = HTTP::Request->new(
        $method,
        $this->_mkuri($path, ( %{$this->{auth_query}}, %{$query_args} )),      # $this->{auth_query} and $query_args combined
        HTTP::Headers->new(%{$this->{auth_header}}, %{$header_args}),          # $this->{auth_header} and $header_args combined
        $this->_serialize({ ( %{$this->{auth_content}}, %{$content_args} ) }), # $this->{auth_content} and $content_args combined
    );

    # Run request
    my $http_response = $this->_request($request);

    # Return
    my $ret = $this->_deserialize($http_response->content);
    if (wantarray) {
        # Return a list containting HTTP status code and deserialized data
        return ( $http_response->code, $ret);
    }
    else {
        # Throw if request failed
        confess('HTTP request failed: ' . $http_response->as_string) if $http_response->code != HTTP_OK;

        # Return just deserialized data
        return $ret;
    }
}

1;
__END__
=head1 NAME

Monitoring::Plugin::REST - Monitoring via RESTful APIs for Nagios and compatibles

=head1 SYNOPSIS

  use Monitoring::Plugin::REST;

  --- Basic usage ---
  my $plugin = Monitoring::Plugin::REST->new(
      usage => 'Monitoring::Plugin usage text here',
      base_uri => '/api/', 
  );

  --- Full example with authentication ---
  my $plugin = Monitoring::Plugin::REST->new(
      usage => 'Monitoring::Plugin usage text here',
      base_uri => '/api/',
      username => 'admin',
      password => '1234',
      authentication => {
          method => 'POST',
          endpoint => '/create_session',
          uri_path_parameters => {},
          request_map => {
              username => [ 'content', 'user' ],
              password => [ 'content', 'pass' ],
          },
          static_query_data => { static_data_for_authentication => 'transferred via uri query param' },
          static_content_data => { static_data_for_authentication => 'transferred via body' },
          response_map => {
            'session_id' => [ 'query', 'session_id' ],
          },
      },
  );

  $plugin->getopts;
  my $data = $plugin->fetch('/status');
  plugin_exit($data->{active} eq 'YES' ? OK : CRITICAL);

=head1 DESCRIPTION

B<Monitoring::Plugin::REST> is a REST handling library built on
Monitoring::Plugin, allowing you to easily write checks for Nagios and
compatible monitoring systems that fetch their data via a RESTful HTTP API.

It takes care of most common tasks when working with RESTful APIs. Currently,
these include:

=over

=item * Transport

=item * Authentication

=item * Serialization

=back

Please see L<TRANSPORT|/TRANSPORT>, L<AUTHENTICATION|/AUTHENTICATION> and L<SERIALIZATION|/SERIALIZATION> for more
information on how these topics are handled respectively.

B<Monitoring::Plugin::REST> is based on
L<Monitoring::Plugin|Monitoring::Plugin>. You are free to use all exported
values, functions and methods provided by
L<Monitoring::Plugin|Monitoring::Plugin>.

=head2 URI CONSTRUCTION

=head3 Step 1: Concatenation

URI construction is handled by B<Monitoring::Plugin::REST>, in an effort to 
simplify implementing often occurring patterns.

URIs used are constructed as:

  host/base_uri/path?key=value

where

=over

=item B<host> is supplied via the command line C<host> parameter

=item B<base_uri> is configured by the developer as an constructor argument

=item B<path> is given in calls to C<fetch()>

=back

After that, the URI is subject to expansion(see L<Expansion|/Step 2: Expansion> below). In a final
step, query parameters are appended as key/value(urlencoded) parameters.

=head3 Step 2: Expansion

You can specify placeholder values in your URIs be enclosing them in C<@>
characters. B<Monitoring::Plugin::REST> will replace these before issuing
requests.

The actual values can be given by using the C<uri_path_parameters> constructor
argument. They can also be set dynamically from authentication responses by
using the C<path> target, see L<AUTHENTICATION|/AUTHENTICATION> for more details.

Suppose the following usage:

  my $plugin = Monitoring::Plugin::REST(
      base_uri => '/foo/@first@/bar',
      uri_path_paramters => { first => 'hello', second => 'world' },
      ...
  );

  $plugin->fetch('GET', '/@second@/baz');

The actual URI used will be

  http://HOST/foo/hello/bar/world/baz

=head2 TRANSPORT

  # Throws an exception if HTTP response status != 200
  my $data = $plugin->fetch(
      'GET'|'POST'|'PUT',
      '/endpoint',
      [query_arguments => {}],
      [content_arguments => {}]
  );

  # Does not throw exceptions
  my ($http_status, $data) = $plugin->fetch(
      'GET',
      '/endpoint',
      [query_arguments => {}],
      [content_arguments => {}]
  );

This librarie's main purpose is to handle the transport of API data.

Fetching a specific piece of information is doneby calling the I<fetch> method
as shown above.

You can supply additional URI parameters in C<query_arguments>, which will be
urlencoded and appended to your request. The same holds true for parameters
sent in your request's body. These are specified by C<content_arguments>. Values
provided there will be serialized and appended to the body.

If needed, authentication will be done automatically. Please refer to
L<AUTHENTICATION|/AUTHENTICATION> for more information on how authentication is handled.

=head2 AUTHENTICATION

There is no formal standard for authentication in RESTful HTTP APIs. As such,
check developers often find themselves implementing the same basic principles,
albeit slighlty different over and over. B<Monitoring::Plugin::REST> tries to
combat that by providing a simple, yet flexible mechanism for expressing
authentication mechanisms.

Authentication is primarily configured via the I<authentication> attribute,
which contains a HASHREF describing what should be done in order to obtain a
session. This description mainly consists of HTTP request parameters as well
as mappings of values to remember and provide in subsequent requests.

  authentication => {
      method => '',
      endpoint => '',
      request_map => {},
  },

Note that cookies will always be saved. There is no need to specify a seperate
mapping for session IDs and the like supplied via cookies.

=over

=item method(SCALAR)

The HTTP method that should be used.

Defaults to C<GET>.

=item endpoint(SCALAR)

API endpoint to use for authenticating. This is appended to the value you've
configured in the I<base_uri> attribute.

Defaults to C</login>.

=item request_map(HASHREF)

  request_map => {
      ATTRIBUTE => [ 'query'|'content', KEY ],
      ...
  },

A HASHREF describing a mapping between B<Monitoring::Plugin::REST> ATTRIBUTEs
and actually sent KEYs. These will be encoded as URI query parameters(I<query>) or
serialized into the request body(I<content>).

Suppose the API expects your username to be given via the parameter C<user_name>
inside your body. You could achieve that by specifying:

  request_map => {
      username => [ 'content', 'user_name' ],
      password => [ 'content', 'pass_word' ],
  },

You can also specify nested structures by seperating path components with a
slash(C</>) like so:

  request_map => {
      'input/username' => [ 'content', 'output/user_name' ],
  },

Defaults to { username => [ 'query', 'user' ], password => [ 'query', 'pass' ] }.

=item static_query_data(HASHREF)

A HASHREF that will be appended, urlencoded, to authentication request URIs. No
further processing will be done.

Defaults to C<{}>,

=item static_content_data(HASHREF)

A HASHREF that will be appended, in  serialized form, to authentication request
bodies. No further processing will be done.

Defaults to C<{}>.

=item response_map(HASHREF)

  response_map => {
      AUTH_KEY => [ 'query'|'path'|'header'|'content', DATA_KEY ],
  },

A HASHREF describing a mapping between received AUTH_KEYs and sent DATA_KEYs.
You can think of this as the inverse of request_map. B<Monitoring::Plugin::REST>
uses this to determine which values to extract from an authentication response
and how to use them in subsequent data fetch requests.

Suppose authentication returns you a session key in C<session_id>. You need to
pass the same value as a URI query parameter named C<session-key>.
This can be done by setting the mapping to:

  response_map => {
      session_id => [ 'query', 'session-key' ],
  },

Just like with C<request_map>, you can specify nested structures by seperating
path components with a slash(C</>).

Defaults to C<{}>.

=back

=head2 SERIALIZATION

Serialization of data sent to the remote host, as well as deserialization of
data received from it, is mostly handled automatically. The most commonly used
format for representing data in RESTful APIs is JSON, which will be used by
default.

However, you can choose to use YAML instead of JSON by setting the
I<representation> attribute to C<yaml>.

=head1 ATTRIBUTES

All attributes documented here must be set by passing them as constructor
arguments.

=over

=item base_uri(SCALAR)

A generic part of your request URI that will be valid for all requests
performed. See L<URI CONSTRUCTION|/URI CONSTRUCTION> for more details on how it is used.

=item uri_path_parameters(HASHREF)

Used during URI expansion to dynamically modify the URI used. See
L<URI CONSTRUCTION|/URI CONSTRUCTION> for more details on how it is used.

=item representation(SCALAR)

Determines what serialization/representation data format to use while
communicating. Can be either C<json> or C<yaml>. See L<SERIALIZATION|/SERIALIZATION> for more
details.

Defaults to C<json>.

=item authentication(HASHREF)

A HASHREF describing what kind of procedure is necessary in order to
authenticate against the host. See L<AUTHENTICATION|/AUTHENTICATION> for more details.

=back

=head1 FUNCTIONS AND METHODS

=over

=item new(LIST)

The constructor. You can pass all arguments that are valid for B<Monitoring::Plugin>
here, as well as all attributes documented under L<ATTRIBUTES|/ATTRIBUTES> above.

Returns a new B<Monitoring::Plugin::REST> object.

=item fetch(SCALAR method, SCALAR path, [ query_arguments => HASHREF ], [ content_arguments => HASHREF ])

An instance method used to actually fetch data from the configured host. It will
handle authentication according to the C<authentication> attribute
(see L>AUTHENTICATION>) and perform data serialization and deserialization.

In list context, returns a list consisting of the HTTP status code and the
deserialized response body.

In scalar context, returns just the deserialized responsy body. Throws an
exception if the request completed with an HTTP status code that is B<NOT>
200(i.e. HTTP_OK).

=item authenticate()

Internally used instance method to perform authentication. This is the method
actually scanning through the C<authentication> attribute and performing the
necessary steps in order to obtain a session.

Feel free to subclass B<Monitoring::Plugin::REST> and override C<authenticate>
if the built-in authentication mechanism isn't flexible enough for your
particular device.

=back

=head1 KNOWN LIMITATIONS

B<Monitoring::Plugin::REST> does not provide any means to support HTTP basic
or digest auth yet. This will be implemted in a later version.

=head1 SEE ALSO

=over

=item check_oceanstor.pl

Simple Huawei OceanStor check based on B<Monitoring::Plugin::REST>.

=item L<Monitoring::Plugin|Monitoring::Plugin> 

Our base class. See it's documentation for more information on general check
functions and methods.

=item https://github.com/comnetgmbh

Official git repository on GitHub.

=back

=head1 AUTHOR

Rika Lena Denia, E<lt>rika.denia@comnetgmbh.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2017 by Rika Lena Denia

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.24.1 or,
at your option, any later version of Perl 5 you may have available.

=cut
