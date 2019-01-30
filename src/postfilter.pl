# Copyright (c) 2005-2019, Paolo Amoroso (Aioe) <freedom@aioe.org>
# All rights reserved.
# Postfilter version 0.9.1

#!/usr/bin/perl

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

############################################################
#                                                          #
#                    Basic configuration                   #
#                                                          #
############################################################

my $use_innconfval	= "true";				# whether to use innconfval in order to determine the right path of
								# each file needed by postfilter. If this is set to "false", paths
								# are read from postingaccess.conf (that in this case is needed to
								# be properly configured).

my $innconfval 		= "/usr/lib/news/bin//innconfval";				# not needed if $use_innshellvar eq "false"
my $config_dir 		= "/etc/news/postfilter/"; 			# used only if $use_innshellvar eq "false"

my @files	= (						# configuration files that need to be loaded before analyzing each post
			"postfilter.conf",
			"rules.conf",
			"access.conf"
		  );
			
my @modules = (							# modules that *always* need to be loaded (they're in pathfilter/)
			"modules/access.pm",
			"modules/banchecks.pm",
			"modules/custom.pm",			# Custom rules must go here
			"modules/exit.pm",
			"modules/legal.pm",
			"modules/mysql.pm",
			"modules/other.pm",
			"modules/rbl.pm",
			"modules/style.pm",
			"modules/checkconfig.pm",
	      );


############################################################
#                                                          #
#                Do not edit before this line              #
#                                                          #
############################################################

########
#
# filter_post(): main subroutine
#
#######


sub filter_post()
{
        $modify_headers = 1;
        my $error_string;

#######################
# Server Status
#######################

        if ( $config{'server_status'} eq "closed" )
        {
		&log( "notice", "Server is closed due server_status is set to \"closed\""); 
                $error_string = &error( 48 );
                return $error_string;
        }
        elsif ( $config{'server_status'} eq "disabled" )
        {
                &log( "notice", "Filter is disabled, everything is accepted", "Message $hdr{'Message-ID'} accepted");
                return "";
        }



#######################
# Load Configurations 
#######################

        my $error_code = &load_config();
        if ( $error_code != 0 )
        {
		if ( $error_code == 42 )
		{
			return "Unable to run innconfval";
		}
		elsif ( $error_code == 43 )
		{
			return "Unable to load some configuration file";
		}
		elsif ( $error_code == 55 )
		{
			return "Unable to load some internal module";
		}
		else
		{
			&log( "err", "Strange load_config return value: $error_code" );
			return "Generic filter failure";
		}
        }


########################
# Syntax check
########################

	$error_code = &syntax_check();
        if ( $error_code != 0 )
        {
                $error_string = &error( $error_code );
                return $error_string;
        }

########################
# Filter Initialization
########################

        $error_code = &init_filter();
        if ( $error_code != 0 )
        {
                $error_string = &error( $error_code );
                return $error_string;
        }

#######################
# WhiteList Check
#######################

        if ( $config{'check_white-list'} eq "true" )
        {
               my $return_value = &check_whitelist();
               if ( $return_value != 0 )
               {
			$error_code = &whitelistchecks();	# return a numerical code

			if ( $error_code == 0 ) 		# Message accepted
			{
                        	$error_code = &success();
                        	if ( $error_code =~ /[0-9]+/ )                # errors
                        	{
                                	$error_string = &error( $error_code );
                                	return $error_string;
                        	}
				return $error_string;
			}
			else					# Message Rejected
			{
				my $error_string = &error( $error_code );
				return $error_string;
			}
               }
        }

#######################
# Forbidden Headers 
#######################

        $error_code = &style_filter();
        if ( $error_code != 0 )
        {
                $error_string = &error( $error_code );
                return $error_string;
        }



#######################
# RBLCheck  
#######################

	if ( $config{'check_rbl'} eq "true" )
	{
		$error_code = &rblcheck();
                if ( $error_code != 0 )
                {
                        $error_string = &error( $error_code );
                        return $error_string;
                }
	}


#######################
# URIBLCheck
#######################

        if ( $config{'check_uribl'} eq "true" )
        {
                $error_code = &check_uribl();
                if ( $error_code != 0 )
                {
                        $error_string = &error( $error_code );
                        return $error_string;
                }
        }



#######################
# TOR Check  
#######################

	if ( $config{'check_tor'} eq "true" )
	{
		$error_code = &check_tor();
		if ( $error_code != 0 )
        	{
                	$error_string = &error( $error_code );
                	return $error_string;
        	}
	}

#######################
# BanList  
#######################

        if ( $config{'check_banlist'} eq "true" )
        {
                $error_code = &check_banlist();
                if ( $error_code != 0 )
                {
                        $error_string = &error( $error_code );
                        return $error_string;
                }
        }

#######################
#  BadWords scanner
#######################

        if (  $config{'check_badwords'} eq "true" )
        {
                $error_code = &badwords();
                if ( $error_code != 0 )
                {
			if ( 
				( $error_code == 38 ) or 	# badwords.conf not found
				( $error_code == 27 )     	# syntax error inside badwords.conf
			   )
			{
				if ( $config{'reject_on_badwords_error'} ne "true" )
				{
					$error_string = &error( $error_code );
					&log( 'crit', $error_string );
				}	
				else
				{
					$error_string = &error( $error_code );
                        	        return $error_string;
				}
			}
			else
			{
	                	$error_string = &error( $error_code );
                        	return $error_string;
			}
                }
        }

#######################
# Check User Rights  
#######################

	if ( $config{'check_users'} eq "true" )
	{
        	$error_code = &check_user();
        	if ( $error_code != 0 )
        	{
                	$error_string = &error( $error_code );
                	return $error_string;
        	}
	}

#######################
# Custom rules
#######################

	if ( $config{'check_custom'} eq "true" )
	{
		$error_code = &custom_filter();
        	if ( $error_code != 0 )
        	{
                	$error_string = &error( $error_code );
                	return $error_string;
        	}
	}

#######################
# Modify Headers  
#######################

        $error_code = &mod_headers();
        if ( $error_code != 0 )
        {
                $error_string = &error( $error_code );
                return $error_string;
        }


#######################
# Log Data before accepting  
#######################

        $error_code = &success();
        if ( $error_code == 44 )		# unable to open legal.log
        {
                $error_string = &error( $error_code );
                return $error_string;
        }

	return $error_code;
	
}

########
#
# whitelistchecks(): Perform reduced checks for whitelisted users
#
#######


sub whitelistchecks()
{
	&log( "notice", "Message $hdr{'Message-ID'} matches a white list entry" );
 
	my $error_code;
       
	if ( $config{'use_banlist'} eq "true" )
        {
        	$error_code = &check_banlist();
                return $error_code if ( $error_code != 0 );
       	}
       	
	$error_code = &style_filter();
	return $error_code if ( $error_code != 0 );

	$error_code = &custom_filter(@access);
	return $error_code if ( $error_code != 0 );

        $error_code = &mod_headers();
	return $error_code if ( $error_code != 0 );
		
	return 0;

}

########
#
# load_config(): build paths and load configuration files and internal modules
#
#######


sub load_config
{	
	my %innshellvar;

#######################
# Run innconfval if needed
#######################

	if ( $use_innconfval eq "true" )
     	{
		my $syntax = $innconfval . " pathdb pathetc pathspool organization mailcmd pathfilter version";

		&log( "debug", "Executing $syntax" );
     		
		open my $SYNTAX, "$syntax|";
		if (!$SYNTAX)
		{
			&log( "err", "Unable to execute $syntax, aborting" );
			return 42;
		}

		my @elem = <$SYNTAX>;

		foreach (@elem)
		{
			chop $_;
			&log( "debug", "Server replies: $_" );
		}

		close $SYNTAX;

		$innshellvar{'file_active'}   	= $elem[0] . "/active";

		$config{'dir_config'} 		= $elem[1] . "/postfilter/";
                $innshellvar{'dir_config'} 	= $config{'dir_config'};
		$innshellvar{'file_badwords'} 	= $config{'dir_config'} . "/badwords.conf";
		$innshellvar{'file_banlist'} 	= $config{'dir_config'} . "/banlist.conf";

                $innshellvar{'file_access'}   	= $elem[2] . "/postfilter/access.log";
                $innshellvar{'file_legal'}    	= $elem[2] . "/postfilter/legal.log";
                $innshellvar{'dir_spool'}     	= $elem[2] . "/postfilter/";
		$innshellvar{'organization'}  	= $elem[3];
		$innshellvar{'sendmail'}      	= $elem[4];
		$innshellvar{'dir_filter'}      = $elem[5];
		$innshellvar{'version'}         = "2.4" if ( $elem[6] =~ /2\.4/ );
		$innshellvar{'version'}         = "2.5" if ( $elem[6] =~ /2\.5/ );
	}
	else
	{
		$config{'dir_config'} = $config_dir; 
	}

	my $tempdir = $config{'dir_config'};

#######################
# Load configuation files
#######################

	&log( "debug", "Loading configuration files from $tempdir" );
	foreach ( @files )
	{
                my $file = "$tempdir/$_";
                my $return;

                &log("debug", "Loading configuration file: $file");
                unless ($return = do $file)
                {
                        &log( "err", "Fatal Error: couldn't parse $file: $@" ) if $@;
                        &log( "err", "Fatal Error: couldn't do $file: $!" )    unless defined $return;
                        &log( "err", "Fatal Error: couldn't run $file" )       unless $return;
                        return 43;
                }
	}
	
	if ( $use_innconfval eq "true" )
	{
		foreach ( keys %innshellvar )		# this is made here in order to avoid that the values in postingaccess.conf
		{					# overwrite the values generated by innshellvar if $use_innconfval is "true"
			$config{$_} = $innshellvar{$_};
		}
	}

#######################
# Load internal modules
#######################

        &log( "debug", "Loading required internal perl modules" );
        foreach ( @modules )
        {
                my $file = "$config{'dir_filter'}/postfilter/$_";
                my $return;

                &log("debug", "Loading module: $file");
                unless ($return = do $file)
                {
                        &log( "err", "Fatal Error: couldn't parse $file: $@" ) if $@;
                        &log( "err", "Fatal Error: couldn't do $file: $!" )    unless defined $return;
                        &log( "err", "Fatal Error: couldn't run $file" )       unless $return;
                        return 55;
                }
        }

     	return 0;
}

########
#
# log(): Log data through nnrpd
#
#######

sub log()    # log( severity, string1, string2.... );
{
        my @strings = @_;

        my $severity = shift(@strings);

        foreach ( @strings )
        {
                INN::syslog( $severity, $_ );
        }
}





