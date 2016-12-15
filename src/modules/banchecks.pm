# Copyright (c) 2005-2009, Paolo Amoroso (Aioe) <freedom@aioe.org>
# All rights reserved.
# Postfilter (banchecks.pm) version 0.8.1

use Date::Parse;
use Digest;
use strict;

our (%hdr, @access, $dbh, $modify_headers, $body, $user, %config, %public_rights_ip, %public_rights_domain, %auth_rights, %ban_limits);
our (%headlist, @quickref, @saved_headers, %whitelist, @distributions, %mysql, %forbidden_crosspost, %scoreset, %maxscore);
our (@nomoderation, @htmlallowed, @htmltags, %extracontent, %forbidden_headers, @forbidden_groups, %dnsbl,@localip);

########
#
# badwords(): Badwords scanner
#
#######

sub badwords()
{
        my ( $total_body_score, $total_subject_score, $id ) = 0;
	my ($host, $time, $pid, $ip, $date, $client_dn, $length, $head_length, $md5, $domain, $gruppi, $followup) = &query_cache_header();


	&log( "debug", "Reading $config{'file_badwords'}" ) if ( $config{'verbose_log'} eq "true" );

#######################
# Read badwords.conf
#######################

        open my $BADWORDS, "$config{'file_badwords'}";
	if (!$BADWORDS)
	{
		&log( "err", "Unable to read data from $config{'file_badwords'}" );	
		return 38;
	}

        my @badwords = <$BADWORDS>;
        close $BADWORDS;

#######################
# Extract useful lines
#######################

        foreach (@badwords)
        {
                $id++;
                if ( $_ !~ /^\n|^\r|^\t|^\#|^\:|^\ |^[\ ][\t]+\n$/ )
                {
                        my ( $regex, $body_score, $subject_score, $comment ) = split( /\:/, $_, 3 );

#######################
# Update the counter if the currebt rule matches
#######################

                        if (
                                ( $regex ne "" ) and
                                (
                                        ( $body_score eq "0" ) or
                                        ( $body_score >   0  )
                                ) and
                                (
                                        ( $subject_score eq "0" ) or
                                        ( $subject_score >   0  )
                                )
                           )
                        {
                                $total_body_score += $body_score       if ( $body =~ /$regex/i );
                                $total_subject_score += $subject_score if ( $hdr{'Subject'} =~ /$regex/i );
                        }
                        else
                        {
                                &log( "err", "Syntax error in $config{'file_badwords'}, line $id" );
                                return 27;
                        }
                }
        }

#######################
# Check score on Subject
#######################

        if (
                ( $config{'scan_subject'} eq "true" ) and
                ( $total_subject_score > $config{'max_score_on_subject'} )
           )
        {
                &log( "err", "Badwords on Subject: score $total_subject_score, max is $config{'max_score_on_subject'}, rejected" );
                return 28;
        }

#######################
# Check score on body
#######################

        if (
                ( $config{'scan_body'} eq "true" ) and
                ( $total_body_score > $config{'max_score_on_body'} )
           )
        {
                &log( "err", "Badwords on Body: score $total_body_score, max is $config{'max_score_on_body'}, rejected" );
                return 29;
        }
}

########
#
# check_whitelist(): Check withelist
#
#######


sub check_whitelist()
{
        foreach ( keys %whitelist )
        {
		my $tmpmid = $hdr{'Message-ID'};
		if ( $hdr{$_} =~ /$whitelist{$_}/i )
		{
	                &log( "debug", "Message $tmpmid: $_: $hdr{$_} matches $whitelist{$_}" );
        	        return 1;
		}
        }

        return 0;
}

########
#
# check_banlist(): Banlist check wrapper (real function is scan_banlist())
#
#######

sub check_banlist()
{
       	my $exit_code    = &scan_banlist( $config{'file_banlist'} );

	if ( 
		($exit_code == -1) or
		($exit_code == 35)
	   )
	{
		if ($config{'reject_on_banlist_error'} eq "false" )
		{
			&log( 'crit', "Syntax error in $config{'file_banlist'}, skipping banlist check" );
			return 0;
		}
		else
		{
			return 35;
		}
	}
	return $exit_code;
}

########
#
# scan_banlist(): Banlist scanner
#
#######

sub scan_banlist($)
{
	my $file = $_[0];

	&log( "debug", "Reading $file" ) if ( $config{'verbose_log'} eq "true" );

#######################
# Read banlist.conf
#######################

	open my $FILE, "$file";
	if (!$FILE)
	{
		&log( "err", "Unable to read data from banlist $file" );
		return -1;
	}

	my @banlist = <$FILE>;
	close $FILE;

	my $id = 0;

#######################
# Scan banlist.conf
#######################

	foreach ( @banlist )
	{
		$id++;
		$_ =~ s/^\ +|^\t+|\n//;

#######################
# Detect whether a line is usable
#######################

		if ( 
			( $_ !~ /^\#/ ) and
			( $_ ne "" )
		   )
		{

#######################
# Check the syntax of each line
#######################


			my @cli   = split( /\:/, $_, 6 );
			my $elem  = @cli;
			return 35 if ( $elem != 6 );

			return 35 if ( 
				( $cli[2] !~ /^log$|^save$|^drop$|^score$|^setmax$|^sum$|^config$/i ) or
				(
					( $cli[3] !~ /^syslog$|^file$|^rnews$|^mbox$|^mail$|^maildir$|^message$|^groups$|^followups$|^head_size$|^total_size$|^body_size$|^lines$/i ) and
			   		( $cli[2] !~ /^score$|^setmax$|^config$/i )
				)
				); 
#######################
# Invoke banlist_action()
#######################
			
			foreach ( keys %hdr )
			{
				my $exit_code = &banlist_action( $cli[2], $cli[3], $cli[4], $file, $id ) 
				if ( 
					( 
						( $_ =~ /$cli[0]/i ) and 
						( $hdr{$_} =~ /$cli[1]/i )
					) or
					(
						( $cli[0] eq "BODY" ) and
						( $body =~ /$cli[1]/i  )
					)
				   );
				
				if ( $exit_code > 0 )
				{
					return $exit_code;
				}
			}
		}
	}

#######################
# Calculate score
#######################

	foreach ( keys %scoreset )
	{
		return 49 
		if ( 
                        ($scoreset{$_} > $config{'score_banlist'} ) or
                        (
                                ($scoreset{$_} > $maxscore{$_}) and
                                ($maxscore{$_} > 0)
                        )
		);
	}

	return 0;
}

########
#
# banlist_action(): Perform a banlist check
#
#######


sub banlist_action($$$$$)
{
	my ($host, $time, $pid, $ip, $date, $client_dn, $length, $head_length, $md5, $domain, $gruppi, $followup) = &query_cache_header();

	my $action = $_[0];
	my $arg1   = $_[1];
	my $arg2   = $_[2];
	my $file   = $_[3];
	my $line   = $_[4];

#######################
# Syntax Check
#######################

	return 35 if ( 
		(
				( $action =~ /^log$/i ) and
				( $arg1 !~ /^syslog$|^file$/ )
		) or
		(
				( $action =~ /^drop$/i ) and
                                ( $arg1 !~ /^syslog$|^file$/i )
		) or
		(
				( $action =~ /^save$/i ) and
                                ( $arg1 !~ /^rnews$|^file$|^mbox$|^mail$|^maildir$|^message$/i )
		) or
		(
				( $action =~ /^sum$/i ) and
			 	( $arg1 !~ /^groups$|^followups$|^total_size$|^head_size$|^body_size$|^lines$/ )
		)
	   );

#######################
# Actions: syslog
#######################

        if ( $arg1 =~ /^syslog$/i )
        {
 		$arg2 =~ s/\%M/$hdr{'Message-ID'}/;
                $arg2 =~ s/\%F/$hdr{'From'}/;
                $arg2 =~ s/\%N/$hdr{'Newsgroups'}/;
                $arg2 =~ s/\%P/$hdr{'Path'}/;
		$arg2 =~ s/\%I/$hdr{'NNTP-Posting-Host'}/;

		my $line = "$file:$line $action: $arg2";

		&log("err", $line ); 
        }

#######################
# Actions: file  
#######################

	if ( $arg1  =~ /^file$/i )
	{
		&log( "debug", "Banlist $file:$line: save data into $arg2", "$file:$line $action: Message-ID $hdr{'Message-ID'}" ) if ( $config{'verbose_log'} eq "true" );
		open my $FILE, ">>$arg2";
		if (!$FILE)
		{
			&log( "err", "Unable to append data into $arg2" );
			return 35;
		}				
		print $FILE "$file:$line $action: Message-ID $hdr{'Message-ID'}\n";
		close $FILE;
	}

#######################
# Actions: message or maildir  
#######################


	if ( 
		( $arg1 =~ /^message$/i ) or
		( $arg1 =~ /^maildir$/i )
	   )
	{
		my $dest_file;

		$dest_file = "$arg2/new/" if ( $arg1 =~ /maildir$/i );	
		$dest_file = "$arg2/" if ( $arg1 =~ /message$/i );
	
		my $time = time();
        	my $pid  = getppid();

		$dest_file .= "$time.$pid.$config{'host'}";

		&log( "notice", "Banlist $file:$line: save article ($hdr{'Message-ID'}) into $dest_file (plain text)" );

		open my $FILE, ">$dest_file";
		if (!$FILE)
		{
			&log( "err", "Unable to save message into $arg2" );	
 			return 35;
		}

		foreach ( keys %hdr )
		{
			print $FILE "$_: $hdr{$_}\n" if ( 
							    ($_ ne "") and 
							    ($_ ne "Received" )
							);	
		}

		print $FILE "\n$body";
		close $FILE;
	}

#######################
# Actions: rnews or mbox  
#######################

	if ( 
		( $arg1 =~ /^rnews$/i ) or
		( $arg1 =~ /^mbox$/i )
	   )
	{
		my $art;
		foreach ( keys %hdr )
                {
			$art .= "$_: $hdr{$_}\n" if (
                        				($_ ne "") and
                                                        ($_ ne "Received" )
                                                    );
                }

                $art .= "\n$body";
		my $size = length($art);
	
		open my $FILE, ">>$arg2";
                if (!$FILE)
                {
                        &log( "err", "Unable to save message into $arg2" );
                        return 35;
                }

		if ( $arg1 =~ /^rnews$/i ) 		
		{
			&log( "notice", "Banlist $file:$line, save article ($hdr{'Message-ID'} into $arg2 (rnews format)");
			print $FILE "#! rnews $size\n";
			print $FILE $art;
		}
		else
		{
			&log( "notice", "Banlist $file:$line, save article ($hdr{'Message-ID'} into $arg2 (mbox format)" );
			
			my $returnpath = $hdr{'Return-Path'};
			$returnpath =~ s/\<|\>//gi;

			my @date = split( /\ /, $hdr{'Date'} );
			chop $date[0];

			print $FILE "From $returnpath $date[0] $date[2] $date[1] $date[4] $date[3]\n";
			print $FILE $art;
			print $FILE "\n";
		}
		close $FILE;		
	}

#######################
# Actions: mail  
#######################

	if ( $arg1 =~ /^mail$/i )
	{
		my $art;
                foreach ( keys %hdr )
                {
                        $art .= "$_: $hdr{$_}\n" if (
                                                        ($_ ne "") and
                                                        ($_ ne "Received" ) and
							($_ ne "To" ) # evita un ciclo con maildrop
                                                    );
                }

                $art .= "\n$body";

		my $sendmail_cli = "$config{'sendmail'} -s \"Message from postfilter\" $arg2";
		&log( "notice", "Banlist $file:$line, mail article to $arg2 ($sendmail_cli)");

		open my $SENDMAIL, "|$sendmail_cli";
		if (!$SENDMAIL)
		{
			&log( "err", "Unable to execute $sendmail_cli" );	
			return 35;
		}
		print $SENDMAIL $art;
	        close $SENDMAIL;

	}

#######################
# Actions: score  
#######################

	if ( 
		($action =~ /^score$/i) and
		($arg1 !~ /^verify$|^clear$/i )
	   )
	{
		$scoreset{$arg1} += $arg2;
	}

        if (
                ($action =~ /^score$/i) and
                ($arg1 =~ /^clear$/i )
           )
        {
                $scoreset{$arg2} = 0;
        }

	if ($action =~ /^setmax$/i)
	{
		$maxscore{$arg1} = $arg2;
	} 

#######################
# Reject if score exceeds the maximum
#######################

        return 49
	if (
                ($action =~ /^score$/i) and
                ($arg1 =~ /verify/i ) and
		(
			($scoreset{$arg2} > $config{'score_banlist'} ) or
			(
				($scoreset{$arg2} > $maxscore{$arg2}) and
				($maxscore{$arg2} > 0)
			)
		)
	);

#######################
# Actions: sum
#######################

	if ($action =~ /^sum$/i)
	{
		if ($arg1 =~ /^groups$/i )
		{
			my @grps = split(/\,/, $hdr{'Newsgroups'} );
			my $grps = @grps;
			$scoreset{$arg2} += $grps;
		}		
		elsif ($arg1 =~ /^followups$/i )
		{
			my @fups = split(/\,/, $hdr{'Followup-To'} );
                        my $fups = @fups;
                        $scoreset{$arg2} += $fups;

		}
		elsif ($arg1 =~ /^head_size$/i )
		{
			my $head = 0;
			foreach ( keys %hdr )
			{
				$head += length($_) + length($hdr{$_}) + 3; #": " e "\n"
			}
			$scoreset{$arg2} += $head;
		}
		elsif ($arg1 =~ /^body_size$/i )
		{
			$scoreset{$arg2} += length($body);
		}
		elsif ($arg1 =~ /^total_size$/i )
		{
                        my $head = 0;
                        foreach ( keys %hdr )
                        {
                                $head += length($_) + length($hdr{$_}) + 3; #": " e "\n"
                        }
			$head += length($body);
			$scoreset{$arg2} += $head;			
		}
		elsif ($arg1 =~ /^lines$/i )
		{
			my @lines = split( /\n/, $body );
			my $num = @lines;
			$scoreset{$arg2} += $num; 
		}

	}

#######################
# Actions: drop  
#######################

        return 34 if ( $action =~ /^drop$/i );

#######################
# Actions: config  
#######################

	if ( $action =~ /^config$/i )
	{
		$config{$arg1} = $arg2;
	}

	return 0;

}

1;
