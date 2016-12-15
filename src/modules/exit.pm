# Copyright (c) 2005-2016, Paolo Amoroso (Aioe) <freedom@aioe.org>
# All rights reserved.
# Postfilter (exit.pm) version 0.8.2

use strict;

use Net::DNS;
use Date::Parse;
use Digest;
use Digest::MD5;
use Digest::SHA1;


our (%hdr, @access, $dbh, $modify_headers, $body, $user, %config, %public_rights_ip, %public_rights_domain, %auth_rights, %ban_limits);
our (%headlist, @quickref, @saved_headers, %whitelist, @distributions, %mysql, %forbidden_crosspost, %scoreset, %maxscore);
our (@nomoderation, @htmlallowed, @htmltags, %extracontent, %forbidden_headers, @forbidden_groups, %dnsbl, @localip );

########
#
# error(): Handle rejected articles
#
#######

sub error($)
{
	my ($host, $time, $pid, $ip, $date, $client_dn, $length, $head_length, $md5, $domain, $gruppi, $followup) = &query_cache_header();
        my $error_code = $_[0];
        my $error_string;

	&log( "err", "Rejecting message $hdr{'Message-ID'}" );

#######################
# Add message to the spool
#######################

	if ( $config{'enable_mysql'} eq "true" )
	{
		&log( "debug", "Adding current message to MySQL backend" );
		my $success = &mysql_addpost( $time, $ip, $error_code, $domain, $length, $head_length, $gruppi, $followup, $user, $md5);
		return $quickref[$success] if ( $success != 0 );
	}
	else
	{
		my $success = &write_access($error_code, @access);
		return $quickref[40] if ( $success != 0 );
	}

#######################
# Accept instead of rejecting, if needed
#######################

	if ( $config{'default_action_on_reject'} eq "accept"  )
	{
		&log( "notice", "Default action on reject is accept, accepting $hdr{'Message-ID'}" );
		&success();
		return "";
	}

#######################
# Discard instead of rejecting, if needed
#######################


	if ( $config{'default_action_on_reject'} eq "discard" )
	{
		&log( "notice", "Default action on reject is drop, dropping $hdr{'Message-ID'}" );
		return "DROP";
	}
        
#######################
# Save before rejecting, if needed
#######################

	if ( $config{'default_action_on_reject'} eq "save" )
        {
		&log( "notice", "Default action on reject is save, saving $hdr{'Message-ID'}" );

                $modify_headers = 1;
                $hdr{'X-Postfilter-Error'} = "Code " . $error_code;
                my $success = &save_message();
		if ( $success != 0 )
		{
			&log("err", "Unable to save message $hdr{'Message-ID'}" );
			return $quickref[41];
		}
		else
		{
			&log("notice", "Message $hdr{'Message-ID'} saved on disk" );
		}
        }

#######################
# Build the string that the user will receive
#######################

        if ( $config{'show_error_code'} eq "true" )
        {
                $error_string = $quickref[$error_code];
        }
        else
        {
                $error_string = "Message rejected";
        }

	&log( "notice", "Error $error_code: $error_string" );

        return $error_string;
}

########
#
# success(): Handle accepted articles
#
#######


sub success()
{
	my ($host, $time, $pid, $ip, $date, $client_dn, $length, $head_length, $md5, $domain, $gruppi, $followup) = &query_cache_header();
	&log( "notice", "Message $hdr{'Message-ID'} accepted" );

        my $success_response = "";

#######################
# Discard instead of accepting, if needed
#######################

	if ( $config{'default_action_on_accept'} eq "discard" )
	{
		&log( "notice", "Default action on accept is drop, dropping $hdr{'Message-ID'}" );
		$success_response = "DROP";
	}
	
	my $error_code = 0;

#######################
# Save before accepting, if needed
#######################

        if ( $config{'default_action_on_accept'} eq "save"    )
        {
		&log( "notice", "Default action on accept is save, saving $hdr{'Message-ID'}" );
                my $success = &save_message();
		if ( $success == 0 )
		{
                	&log( "notice", "Message $hdr{'Message-ID'} saved on disk" );
		}
		else
                {
			&log( "err", "Unable to save message $hdr{'Message-ID'}" )   if ($success != 0);
        		return $quickref[41];
		}
	}

#######################
# Reject instead of accepting, if needed
#######################


	if ( $config{'default_action_on_accept'} eq "reject"  )
	{
		&log( "notice", "Default action on accept is reject, rejecting $hdr{'Message-ID'}" );
		$success_response = &error( 47 );
	}

#######################
# Add message to the spool
#######################

	if ( $config{'enable_mysql'} eq "true" )
	{
                &log( "debug", "Adding current message to MySQL backend" );
                my $success = &mysql_addpost( $time, $ip, $error_code, $domain, $length, $head_length, $gruppi, $followup, $user, $md5);
                return $quickref[$success] if ( $success != 0 );
	}
	else
	{
                my $success = &write_access($error_code, @access);
                return $quickref[40] if ( $success != 0 );
	}

#######################
# Write legal summary
#######################

	&log( "debug", "Writing legal summary" );
	if ( $config{'legal_summary'} eq "true" )
	{
		my $return_value = &legal_summary();
		$success_response = $quickref[$return_value] if ( $return_value != 0 );		
	}

#######################
# Delete Cache header
#######################

	&delete_cache_header(); 		# Beware: if it's cancelled before this point legal summary doesn't work

        return $success_response;
}

1;
