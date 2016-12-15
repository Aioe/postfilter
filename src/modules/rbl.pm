# Copyright (c) 2005-2009, Paolo Amoroso (Aioe) <freedom@aioe.org>
# All rights reserved.
# Postfilter (rbl.pm) version 0.8.1

use Net::DNS;
use Digest;
use strict;

our (%hdr, $dbh,  @access, $modify_headers, $body, $user, %config, %public_rights_ip, %public_rights_domain, %auth_rights, %ban_limits);
our (%headlist, @quickref, @saved_headers, %whitelist, @distributions, %mysql, %forbidden_crosspost, %scoreset, %maxscore);
our (@nomoderation, @htmlallowed, @htmltags, %extracontent, %forbidden_headers, @forbidden_groups, %dnsbl, @localip );

########
#
# rblcheck(): Check client's ip against RBLs
#
#######

sub rblcheck()
{
	my ($host, $time, $pid, $ip, $date, $client_dn, $length, $head_length, $md5, $domain, $gruppi, $followup) = &query_cache_header();

	&log("debug", "Starting RBL check for $ip" ) if ($ip ne "");

#######################
# Messages that come from stdin
#######################

	if ( $ip eq "" )
        {
                &log("notice", "Message comes from stdin, DNSLBL check is not needed" );
        }

#######################
# RBL Check
#######################


	elsif ( $ip ne "127.0.0.1" )
	{
		foreach (keys %dnsbl)
		{
			my $dnsblserver = $_;
			my $return_errors = $dnsbl{$_};
 
			&log( "notice", "Checking $ip in $dnsblserver DNSBL" );
			
			my $success = &DNSBLQuery( $ip, $dnsblserver, $return_errors );

			if ( $success == 0 )
			{
				&log("notice", "IP $ip is not listed in $_");
			}
			else
			{
				&log( "err", "IP $ip is listed in $dnsblserver DNSBL, article rejected" );
				return 56;
			}
		}
	}

#######################
# Messages that come from localhost
#######################

	else
	{
		&log("notice", "Message comes from localhost, DNSBL check is not needed" );
	}
	return 0;
}

########
#
# check_tor(): Check whether the client's ip is a TOR node
#
#######

sub check_tor()
{
        my ($host, $time, $pid, $ip, $date, $client_dn, $length, $head_length, $md5, $domain, $gruppi, $followup) = &query_cache_header();

#######################
# Messages that come from stdin
#######################

	if ( $ip eq "" )
	{
		&log( "notice", "Message comes from stdin that can't be a TOR router, TOR check is not needed" );
		return 0;
	}

#######################
# Messages that come from localhost
#######################

	elsif ( $ip eq "127.0.0.1" )
	{
		&log( "notice", "Message comes from $ip that can't be a TOR router or is an onion domain, TOR check is not needed" );
                return 0;
	}

#######################
# TOR Check
#######################

	else 
	{
		&log( "debug", "Check whether $ip is a TOR exit node" );
		foreach (@localip)
		{
			my @elem = split(/\./, $_ );			# split server ip
			my $dnsbluri = "119.$elem[3].$elem[2].$elem[1].$elem[0].ip-port.exitlist.torproject.org";
                	&log( "debug", "Detecting TOR router at $dnsbluri" );

			my $success = DNSBLQuery( $ip, $dnsbluri, ".+" );

#######################
# Articles that don't come from TOR
#######################

                	if ( $success == 0 )
                	{
	                	&log("debug", "IP $ip is not listed in $dnsbluri");
                	}
                	else
                	{

#######################
# Reject posts from TOR
#######################

                       		if ( $config{'tor_network'} eq "reject" )
				{
					&log( "err", "IP $ip is a TOR exit node, article rejected" );
                       			return 50;
				}
		
#######################
# Mark posts from TOR
#######################
		
				if ( $config{'tor_network'} eq "mark" )
				{
					&log( "notice", "IP $ip is a TOR exit node, article marked" );
					$modify_headers = 1;
					$hdr{'X-TOR-Router'} = $ip;
					$hdr{'Path'} = "tor-network!not-for-mail"; 	# preloaded paths are not a great idea with TOR
					&delete_headers('NNTP-Posting-Host');           # this is useless here
					return 0;
				}
               		}
		}
	}

        return 0;
}

########
#
# DNSBLQuery($ip, $server, $errors): Check whether $ip matches $server RBL list with a value of $errors
#
#######

sub DNSBLQuery($$$) # IP, server, errors
{
	my $ip = $_[0];
	my $server = $_[1];
	my $errors = $_[2];

	my $res = Net::DNS::Resolver->new;

#######################
# Build the DN for querying
#######################

	my @elem = split( /\./, $ip );
	my $query;

	for ( my $n = 3; $n>-1; $n-- )
	{
        	$query .= "$elem[$n].";
	}

	$query .= "$server";

#######################
# Query the DNSBL
#######################

	my $packet = $res->query($query);
	my @answers = $packet->answer if ($packet);

#######################
# Analyze results
#######################

	if ( @answers > 0 )
	{
		foreach (@answers)
		{
        		my $line = $_->string;
        		my @parts = split(/\t/, $line );
			&log( "debug", "DNSBL $server replies $parts[4] about $ip" );

			if ( $parts[4] =~ /$errors/i )
			{
				&log( "err", "About $ip DNSBL server replies $parts[4] that matches $errors" );
				return 1;
			}
			
		}

	}
	return 0;
}

########
#
# check_uribl(): Check URIBLs
#
#######

sub check_uribl()
{
	my $number = 0;

#######################
# Check whether the body includes URIs
#######################

        while ( $body =~ /(http\:\/\/\S+)[\s|\n]/gi )
        {
                $number++;
	}

#######################
# If the body includes some URI
#######################

	if ( $number > 0 )
	{
		my $success;
		&log( "notice", "Checking $number body URIs agains URIBLs" );

#######################
# Check SURBL if requested
#######################

		if ( $config{'check_surbl'} eq "true" )
		{		
			&log( "debug", "Checking SURBL ...." );
			$success = &check_surbl();
			return $success if ($success > 0);
		}

#######################
# Check URIBL.com if requested
#######################

		if ( $config{'check_uriblcom'} eq "true" )
		{	
			&log( "debug", "Checking URIBL.com ...." );
			$success = &check_uriblcom();
			return $success;
		}
	}

#######################
# No URI in the body
#######################

	else
	{
		&log( "notice", "No URI in the body, skipping URIBL checks" );
	}

	return 0;
}

########
#
# check_surbl(): Check SURBL
#
#######

sub check_surbl()
{

#######################
# Load domains list
#######################

	my $tldlist = "$config{'dir_filter'}/data/two-level-tlds";

	open my $TLD, "$tldlist";
	if (!$TLD)
	{
		&log( "err", "Unable to load top level domains file ($tldlist)" );
		return 59;
	}
	my @tlds = <$TLD>;
	close $TLD;

	my $number = 0;

#######################
# Extract URIs from the body and build the dn used for querying
#######################

	while ( $body =~ /(http\:\/\/\S+)[\s|\n]/gi )
	{
		my $url = $1;
		$number++;

		my $curl = &create_url($url, 2);
		next if (!$curl);
			
		foreach ( @tlds )
		{
			$_ =~ s/\ .+$|\n|\t.+$//;
			if ( $_ eq $curl )
			{
				&log( "debug", "URIBL Check: $curl is a known second level domain, adding a third level" );
				$curl = &create_url($url, 3);
			}
		}

		my $uri = "$curl.multi.surbl.org";
		
#######################
# Query SURBL
#######################

		my $status = &URIBLQuery($uri,$url);
		if ($status != 0)
		{
			&log( "err", "Body includes a link to $curl that matches surbl.com URIBL, rejected" );
			return 60;
		}
		&log( "debug", "URIBL Check $number: $url ($uri) doesn't match SURBL" );
	}
	&log( "notice", "SURBL URIBL Check passed, found $number URIs that don't match SURBL" );

	return 0;
}

########
#
# check_uriblcom(): Check URIBL.com
#
#######

sub check_uriblcom()
{

#######################
# Extract URIs from the body
#######################

	my $number;
	while ( $body =~ /(http\:\/\/\S+)[\s|\n]/gi )
	{
		my $url = $1;
		$number++;

		my $curl = &create_url($url, 2);
		next if (!$curl);
		
		my $uri = "$curl.white.uribl.com";

#######################
# Query URIBL.com whitelist
#######################

		my $status = &URIBLQuery($uri,$url);
		if ($status != 0)
		{
			&log( "notice", "URIBL Check $number: $url is whitelisted by URIBL.com" );
			next;
		}
		
#######################
# URIBL.com common second level domains
#######################

		if ( $url =~ /uribl\.com|blogspot\.com|by\.ru|narod\.ru|front\.ru|googlegroups\.com|geocities\.com|tripod\.com|potcha\.ru|nm\.ru|pochtamt\.ru|land\.ru|newmail\.ru|hotbox\.ru|rbcmail\.ru/i )
		{
			&log( "debug", "URIBL Check $number: $curl is a known second level domain, adding a third level" );
			$curl = &create_url($url, 3);
		}


#######################
# Query URIBL.com main list
#######################
	
		$uri = "$curl.multi.uribl.com";
		$status = &URIBLQuery($uri,$url);
		if ($status != 0)
		{
			&log( "err", "Body includes a link to $curl that matches uribl.com URIBL, rejected" );
			return 61;
		}

		&log( "debug", "URIBL Check $number: $url ($uri) doesn't match URIBL.com" );
	}
	&log( "notice", "URIBL.com URIBL Check passed, found $number URIs that don't match URIBL.com" );
	return 0;
}

########
#
# create_url($url, $number): Create URIBL.com DN
#
#######

sub create_url($$)
{
	my $url = $_[0];
	my $number = $_[1];
	my $curl;

#######################
# Remove useless URI prefix
#######################
	
	$url =~ s/http\:\/\///i;
	$url =~ s/\/.+$//g;
	$url =~ s/\///g;
	
#######################
# Skip common domains
#######################


	if ( $url =~ /gmail\.com|yahoo\.com|w3\.org|msn\.com|com\.com|yimg\.com|hotmail\.com|doubleclick\.net|flowgo\.com|ebaystatic\.com|aol\.com/i)
	{
		&log( "notice", "Skipping URIBL check for $url since it's a common domain" );
		return undef;
	}

#######################
# If the host is numerical, build the query
#######################

	if ( $url =~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ )
	{
		my @num = split( /\./, $url );
		$curl = "$num[3].$num[2].$num[1].$num[0]";
	} 

#######################
# Build the query
#######################

	else 
	{
		my @domains = split( /\./, $url );
		my $domains_number = @domains;
		my $dem;
		if ( $domains_number > 1 )
		{
			$dem = $domains_number - 1;
		}
		else
		{
			$dem = $domains_number;
		}
		if ( $number == 2 )
		{
			$curl = "$domains[($dem-1)].$domains[$dem]";
		} else
		{
			if ( $domains_number > 2 )
			{
			      $curl = "$domains[($domains_number-3)].$domains[($domains_number-2)].$domains[$domains_number-1]";
			} else
			{
				$curl = "$domains[($dem-1)].$domains[$dem]";
			}
		}
	}
	return $curl;
}

########
#
# URIBLQuery($uri, $server): Query URIBL.com 
#
#######

sub URIBLQuery($$)
{
	my $uri = $_[0];
	my $url = $_[1];
	my $res = Net::DNS::Resolver->new;
	my $packet = $res->query($uri);
	my @answers = $packet->answer if ($packet);
	if ( @answers > 0 )
	{
	      foreach (@answers)
	      {
		    my $line = $_->string;
		    my @parts = split(/\t/, $line );
		    &log( "debug", "URIBL replies $parts[4] about $uri" );
	      }
	      return 1;
	 }
	return 0;
}

1;
