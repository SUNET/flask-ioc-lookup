#!/usr/bin/env perl
 
use strict;
use warnings;
 
use Data::Dumper;
use HTTP::Request::Common qw(POST);
use JSON::MaybeXS qw(encode_json decode_json);
use LWP::UserAgent;
 
my $apitoken = '<APITOKEN>';
my $endpoint = '<IOC_LOOKUP_URL>';
my $data = {'search' => $ARGV[0]};

my $ua = LWP::UserAgent->new();
my $req = POST $endpoint,
    Content_Type => 'application/json',
    Accept => 'application/json',
    'api_token' => $apitoken,
    Content => encode_json($data);
 
my $res = $ua->request($req);
print Dumper($res->content);