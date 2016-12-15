# Copyright (c) 2005-2016, Paolo Amoroso (Aioe) <freedom@aioe.org>
# All rights reserved.
# Postfilter (legal.pm) version 0.8.2

use strict;

our (%hdr, $dbh,  @access, $modify_headers, $body, $user, %config, %public_rights_ip, %public_rights_domain, %auth_rights, %ban_limits);
our (%headlist, @quickref, @saved_headers, %whitelist, @distributions, %mysql, %forbidden_crosspost, %scoreset, %maxscore);
our (@nomoderation, @htmlallowed, @htmltags, %extracontent, %forbidden_headers, @forbidden_groups,%dnsbl,@localip);

sub legal_summary()
{
	my ($host, $time, $pid, $ip, $date, $client_dn, $length, $head_length, $md5, $domain, $gruppi, $followup) = &query_cache_header();
	&log( "debug", "Appending legal logs to $config{'file_legal'}" );
	
        open my $LEGAL, ">>$config{'file_legal'}";
        if (!$LEGAL)
        {
	        &log( "err", "Unable to write data into legal log ($config{'file_legal'})" );
                return( 44 );
        }

	my $source;
	if ( $ip eq "" )
	{
		$source = "stdin";
	}
	else
	{
		$source = $ip;
	}

       	print $LEGAL "$time\t$hdr{'Message-ID'}\t$source\t$user\n";
       	close $LEGAL;
        return 0;

}

