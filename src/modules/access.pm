# Copyright (c) 2005-2019, Paolo Amoroso (Aioe) <freedom@aioe.org>
# All rights reserved.
# Postfilter (access.pm) version 0.9.1

use strict;

use Net::DNS;
use Date::Parse;
use Digest;
use Digest::MD5;
use Digest::SHA1;
use DBI;


our (%hdr, $dbh, @access, $modify_headers, $body, $user, %config, %public_rights_ip, %public_rights_domain, %auth_rights, %ban_limits);
our (%headlist, @quickref, @saved_headers, %whitelist, @distributions, %mysql, %forbidden_crosspost, %scoreset, %maxscore);
our (@nomoderation, @htmlallowed, @htmltags, %extracontent, %forbidden_headers, @forbidden_groups, %dnsbl, @localip );

########
#
# init_filter(): build Cache header, mysql init and expire, build active
#
#######


sub init_filter()
{

#######################
# Build Cache: Header and variables
#######################

	&create_cache_header();

	my ($host, $time, $pid, $ip, $client_dn, $length, $head_length, $md5, $domain, $gruppi, $followup) = &query_cache_header();
	my $mid = $hdr{'Message-ID'};

	&log( "notice", "Analyzing message $mid, MD5 $md5");

#######################
# MYSQL: Connection
#######################

	if ( $config{'enable_mysql'} eq "true" )
	{
		my $success = &mysql_init();
		return $success if ( $success != 0 );
	}

#######################
# Read access file (mysql disabled)
#######################

	else
	{
		my $success;
		($success,@access) = read_access();
		if ($success == 1)
		{
			&log( "err", "Unable to read access.log from file" );
			return 40;
		}
	}

        return 0;
}

########
#
# check_user(): Check whether the sender has the right to post
#
#######


sub check_user()
{
	my ($host, $time, $pid, $ip, $client_dn, $length, $head_length, $md5, $domain, $gruppi, $followup) = &query_cache_header();

#######################
# Authenticated user...
#######################

        if (
                ( $config{'server_type'} eq "auth" ) or
                (
                        ( $config{'server_type'} eq "both" ) and
                        ( $user !~ /$config{'public_user_id'}/i )
                )
          )
        {
		my $error_code = &check_rights("ID");
		return $error_code if ( $error_code != 0 );
        }

#######################
# Unauthenticated user
#######################

        else
        {
		my $error_code = &check_rights("IP");
                return $error_code if ( $error_code != 0 );

		if ( $config{'enable_domain_check'} eq "true" )
		{
			my $error_code = &check_rights("DN");
                	return $error_code if ( $error_code != 0 );
		}

        }
        return 0;
}

########
#
# access_control($type): Read @access than detect which actions where made by the sender in the past
#
#######


sub access_control($)
{
	my ($host, $time, $pid, $ip, $client_dn, $length, $head_length, $md5, $domain, $gruppi, $followup) = &query_cache_header();
        my $arg = $_[0];

        my ( $time_post, $ip_old, $domain_old, $code_old, $size_old, $head_old, $groups_old, $followups_old, $user_old, $md5_old, $md5_mark, $mid_old ) = 0;

        my %access;
        $access{'multipost'} = 0;

#######################
# Scan @access
#######################

        foreach ( @access )
        {
                ( $time_post, $ip_old, $domain_old, $code_old, $size_old, $head_old, $groups_old, $followups_old, $user_old, $md5_old, $mid_old ) = split( "\t", $_, 11 );
                chop $mid_old;

#######################
# Multipost
#######################

                $access{'multipost'}++ if (($md5_old eq $md5) and ($code_old == 0)); # spammers send articles from varius IP, check must be done regardless source ip
										     # multipost must be calculated using *accepted* articles only
                $size_old += $head_old;

#######################
# Check whether each article was sent by the current sender
#######################

                if ( 
			(
                        	( $ip_old eq $ip ) and
                        	( $arg eq "IP" )
			) or
			(
				( $domain_old eq $domain ) and
	                        ( $arg eq "DN" )
			) or
			(
				( $user_old eq $user) and
                        	( $arg eq "ID" )
			)
                   )
                {

#######################
# If so, update the return hash
#######################

                        $access{'max_articles'}++ if ( $time_post > $time - $config{'period'} );
                        $access{'max_short_articles'}++   if ( $time_post > $time - $config{'short_period'} );

                        $access{'max_total_errors'}++ if (
                                                                ( $code_old > 0 ) and
                                                                ( $time_post > $time - $config{'period'} )
                                                        );

                        $access{'max_short_errors'}++ if (
                                                                ( $code_old > 0 ) and
                                                                ( $time_post > $time - $config{'short_period'} )
                                                        );

                        $access{'max_total_size'} += $size_old if ( $time_post > $time - $config{'period'} );
                        $access{'max_short_size'} += $size_old if ( $time_post > $time - $config{'short_period'} );

                        $access{'max_total_groups'} += $groups_old if ( $time_post > $time - $config{'period'} );
                        $access{'max_short_groups'} += $groups_old if ( $time_post > $time - $config{'short_period'} );

                        $access{'max_total_followups'} += $followups_old if ( $time_post > $time - $config{'period'} );
                        $access{'max_short_followups'} += $followups_old if ( $time_post > $time - $config{'short_period'} );
                }
        }

#######################
# Return the hash
#######################

        return %access;
}

########
#
# read_access(): Read @access from the disk
#
#######


sub read_access()
{
        &log( "debug", "Trying to read $config{'file_access'}" );

        open my $ACCESS, "$config{'file_access'}";
        if (!$ACCESS)
        {
                &log( "err", "Unable to read data from $config{'file_access'}" );
                return (1,0);
        }

        my @file_access  = <$ACCESS>;
        close $ACCESS;

        return (0,@file_access);
}


########
#
# write_access(): write to disk and expire @access 
#
#######


sub write_access($$)
{
        my $error_code = $_[0];
        shift @_;
        my @access = @_;
        my ($host, $time, $pid, $ip, $client_dn, $length, $head_length, $md5, $domain, $gruppi, $followup) = &query_cache_header();
        my ($expired_messages,$total_messages) = 0;

        $total_messages = 1;

#######################
# Expire old records
#######################

        foreach ( @access )
        {
                my @data = split( /\t/, $_ );
                if ( $data[0] < $time - $config{'trash_period'} )
                {
                        $_ = "";
                        $expired_messages++;
                }
                $total_messages++;

        }

        &log( "debug", "Expiring $config{'file_access'}: $expired_messages expired/$total_messages total messages" );
        &log( "debug", "Writing new data into $config{'file_access'}" );

#######################
# Open access file (access.log)
#######################

	$ip = "stdin" if ($ip eq "");

# if access file doesn't exist...

        if ( !-e $config{'file_access'})
	{
		&log( "notice", "$config{'file_access'} doesn't exist");

# try to create it

		open(FW,">$config{'file_access'}");
		print FW "";
		close FW;

# if creation doesn't work (due permission problems), return error

		if ( !-e $config{'file_access'})
		{
			&log( "err", "Unable to create $config{'file_access'}");
			return 1;
		} else {
			&log( "notice", "$config{'file_access'} created");
		}
	}

        open my $ACCESS, ">$config{'file_access'}";
        if (!$ACCESS)
        {
                &log( "err", "Unable to write access file $config{'file_access'}");
                &log( "debug", "Error $!" );
                return 1;
        }

	my $mid = $hdr{'Message-ID'};

#######################
# Write old, unexpired lines
#######################

        print $ACCESS  @access;

#######################
# Write current line
#######################

        print $ACCESS  "$time\t$ip\t$domain\t$error_code\t$length\t$head_length\t$gruppi\t$followup\t$user\t$md5\t$mid\n";
        close $ACCESS;

        &log( "debug", "Writing successfully done" );

        return 0;

}


########
#
# check_rights(): Check whether the current IP/Domain/UserID has the right to post
#
#######

sub check_rights($)
{
	my $arg = $_[0];
	my ($host, $time, $pid, $ip, $client_dn, $length, $head_length, $md5, $domain, $gruppi, $followup) = &query_cache_header();

	my %rights;

#######################
# Set right configuration data
#######################

	if ( $arg eq "IP" )
	{
		%rights = %public_rights_ip;
		&log ( "notice", "Checking user's rights: IP $ip" );
	} elsif ( $arg eq "DN" )
	{
		%rights = %public_rights_domain;
		&log( "notice", "Checking user's rights: Domain $domain" );
	} elsif ( $arg eq "ID" )
	{
		%rights = %auth_rights;
		&log( "debug", "Checking user's rights: UserID $user" );
	}


#######################
# Multipost check
#######################

        my %access_id = &access_control($arg);
        &log( "notice", "Multipost:  $access_id{'multipost'}" ); 
        if ( $access_id{'multipost'} > $config{'maximum_multipost'} )
        {
 	       &log( "err", "Found $access_id{'multipost'} past articles with the same MD5 hash $md5 (maximum is $config{'maximum_multipost'}), rejected");
               return 30;
        }

#######################
# Access Rights Check
#######################

        foreach ( keys %access_id )
        {
        	if ( $access_id{$_} >= $rights{$_} )
		{                
			my $logerror;
			if ( $arg eq "IP" )
			{
	                	$logerror = "For the IP address $ip,";
			} elsif ( $arg eq "ID" )
			{
				$logerror = "For the user $user,";
			} elsif ( $arg eq "DN" )
			{
				$logerror = "For the IP address $ip, domain $ip,"; 
			}

			&log( "err", "$logerror $_ is $access_id{$_}, maximum allowed is $rights{$_}, rejected" );
       
 	                return 30 if ( $_ eq "multipost" );
			
			if ( $_ eq "max_articles" )
			{
				return 31 if ( $arg eq "IP" );
				return 32 if ( $arg eq "DN" );
				return 33 if ( $arg eq "ID" );
			}

                        if ( $_ eq "max_short_articles" )
                        {
                                return 70 if ( $arg eq "IP" );
                                return 71 if ( $arg eq "DN" );
                                return 72 if ( $arg eq "ID" );
                        }


			if ( $_ eq "max_total_errors" )
			{
				return 64 if ( $arg eq "IP" );
                                return 65 if ( $arg eq "DN" );
                                return 66 if ( $arg eq "ID" );
			}
                        
			if ( $_ eq "max_short_errors" )
                        {
                                return 67 if ( $arg eq "IP" );
                                return 68 if ( $arg eq "DN" );
                                return 69 if ( $arg eq "ID" );
                        }

                        if ( $_ eq "max_short_size" )
                        {
                                return 73 if ( $arg eq "IP" );
                                return 74 if ( $arg eq "DN" );
                                return 75 if ( $arg eq "ID" );
                        }

                        if ( $_ eq "max_total_size" )
                        {
                                return 76 if ( $arg eq "IP" );
                                return 77 if ( $arg eq "DN" );
                                return 78 if ( $arg eq "ID" );
                        }

                        if ( $_ eq "max_short_groups" )
                        {
                                return 79 if ( $arg eq "IP" );
                                return 80 if ( $arg eq "DN" );
                                return 81 if ( $arg eq "ID" );
                        } 

                        if ( $_ eq "max_total_groups" )
                        {
                                return 82 if ( $arg eq "IP" );
                                return 83 if ( $arg eq "DN" );
                                return 84 if ( $arg eq "ID" );
                        }

                        if ( $_ eq "max_short_followups" )
                        {
                                return 85 if ( $arg eq "IP" );
                                return 86 if ( $arg eq "DN" );
                                return 87 if ( $arg eq "ID" );
                        } 

                        if ( $_ eq "max_total_followups" )
                        {
                                return 88 if ( $arg eq "IP" );
                                return 89 if ( $arg eq "DN" );
                                return 90 if ( $arg eq "ID" );
                        }


                }
        }
	return 0;
}


1;
