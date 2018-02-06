# Copyright (c) 2005-2018, Paolo Amoroso (Aioe) <freedom@aioe.org>
# All rights reserved.
# Postfilter (mysql.pm) version 0.8.3

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
# mysql_init(): MySQL initialization
#
#######


sub mysql_init()
{
		my ($host, $time, $pid, $ip, $client_dn, $length, $head_length, $md5, $domain, $gruppi, $followup) = &query_cache_header();
		&log( "debug", "Trying to connect MYSQL server $mysql{'server'}, user $mysql{'user'}, database $mysql{'database'}" );

#######################
# MYSQL: Connect
#######################

		my $driver = DBI->install_driver('mysql');
		my $dsn = "DBI:mysql:$mysql{'database'}:$mysql{'server'}";

		eval { $dbh = DBI->connect( $dsn, $mysql{'user'}, $mysql{'password'}, {RaiseError => 1, PrintError => 0 }); };
	
		if ($@)
		{
			&log( "err", "Mysql error: $DBI::errstr" );
			return(36);
		}

#######################
# MYSQL: Expire old records
#######################
	
		my $time_expire = time() - $config{'trash_period'};
		
		my $sql = "DELETE from postfilter where time < ?";
		&log( "debug", "SQL Query: $sql ($time_expire)" );
		
		my $sth;

		eval { $sth = $dbh->prepare( $sql ); };

		if ($@)
		{
			&log( "err", "Unable to prepare the SQL statement: $DBI::errstr" );
			$dbh->disconnect();
			return(45);
		}

		&log( "debug", "Trying to expire MYSQL records older than $time_expire" );

		eval { my $success = $sth->execute($time_expire); };
		
		if ($@)
		{
			&log( "err", "Query Execution failed during expire" );
			$dbh->disconnect();
			return 45;
		}

		$sth->finish();

#######################
# MYSQL: Query for past articles: build a query
#######################
	
		if ( $config{'server_type'} eq "public" )
		{ 
			$sql = "SELECT * from postfilter where domain = ?";
		}
		elsif ( $config{'server_type'} eq "auth" ) 
		{
			$sql = "SELECT * from postfilter where user = ?";
		}
		elsif( $config{'server_type'} eq "both" )
		{
			$sql = "SELECT * from postfilter where domain = ?" if ( $user eq $config{'public_user_id'});
			$sql = "SELECT * from postfilter where user = ?" if ( $user ne $config{'public_user_id'});
		}

		&log( "debug", "SQL Query: $sql" );

########################
# Prepare the query
########################


		eval { $sth = $dbh->prepare( $sql ); };

		if ($@)
		{
			&log( "err", "Unable to prepare the SQL statement: $DBI::errstr" );
			$dbh->disconnect();
			return(46);
		}

########################
# Execute the query
########################


		my $success;
		eval { $success = $sth->execute( $domain ); } 
							if (
								( $config{'server_type'} eq "public" ) or
								(
									( $config{'server_type'} eq "both" ) and
									( $user eq $config{'public_user_id'})
								)
						  	   );
                if ($@)
                {
                        &log( "err", "Unable to execute the query ($sql): $DBI::errstr" );
                        $dbh->disconnect();
                        return(46);
                }


		eval { $success = $sth->execute( $user ); } 
							if ( 
								( $config{'server_type'} eq "auth" ) or
								(
									( $config{'server_type'} eq "both" ) and
									( $user ne $config{'public_user_id'})
								)
						   	   );

                if ($@)
                {
                        &log( "err", "Query Execution failed during SELECT" );
			$dbh->disconnect();
                        return 45;
                }

#######################
# MYSQL: Build list of previous articles
#######################

		my ( $cur_id, $cur_time, $cur_domain, $cur_error_code, $cur_length, $cur_head_length, $cur_groups, $cur_followups, $cur_user, $cur_md5, $cur_IP );

		while ( ( $cur_id, $cur_time, $cur_domain, $cur_error_code, $cur_length, $cur_head_length, $cur_groups, $cur_followups, $cur_user,$cur_md5, $cur_IP ) = $sth->fetchrow_array())
		{
			my $line = "$cur_time\t$cur_IP\t$cur_domain\t$cur_error_code\t$cur_length\t$cur_head_length\t$cur_groups\t$cur_followups\t$cur_user\t$cur_md5\n";
			push( @access, $line );
		}
		
		$sth->finish();

		return(0);

}

########
#
# mysql_addpost(time, ip, error_code, domain, length, head_length, groups, followups, user, md5): Add a row about an article in the  MySQL database
#
#######


sub mysql_addpost($$$$$$$$$$)
{
	my $time	= $_[0];
	my $ip	 	= $_[1];
	my $error_code  = $_[2];
	my $domain	= $_[3];
	my $length	= $_[4];
	my $head_length = $_[5];
	my $gruppi 	= $_[6];
	my $followup 	= $_[7];
	my $user 	= $_[8];
	my $md5 	= $_[9];

	if ( ($error_code == 36) or ($error_code == 45) or ($error_code == 46) )
	{
		&log( "err", "Unable to write data into the MySQL backend" );
		return $error_code;
	}

	my $sql = "INSERT into postfilter (time, ip, error_code, domain, length, head_length, groups, followups, user, md5 ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ? )";
        &log( "debug", "SQL Query: $sql" );

	my $sth;

        eval { $sth = $dbh->prepare( $sql ); };

        if ($@)
        {
	        &log("err", "Unable to prepare the SQL statement: $DBI::errstr");
                $dbh->disconnect();
                return(46);
        }

        eval { $sth->execute( $time, $ip, $error_code, $domain, $length, $head_length, $gruppi, $followup, $user, $md5); };

        if ($@)
        {
		&log( "err", "Unable to prepare the SQL statement: $DBI::errstr" );
                $dbh->disconnect();
                return(46);
        }

	
	eval {
        	$sth->finish();
		$dbh->disconnect(); # BEWARE!!! This line is needed in order to *close* the connection with MYSQL server and *MUST* be the last
	     };

        if ($@)
        {
                &log( "err", "Some error happened closing the connection with MySQL: $DBI::errstr" );
                return(46);
        }


	return 0;
}


1;
