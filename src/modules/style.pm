# Copyright (c) 2005-2009, Paolo Amoroso (Aioe) <freedom@aioe.org>
# All rights reserved.
# Postfilter (style.pm) version 0.8.1

use Date::Parse;
use Digest::HMAC;
use Digest;
use strict;

our (%hdr, $dbh, @access, $modify_headers, $body, $user, %config, %public_rights_ip, %public_rights_domain, %auth_rights, %ban_limits);
our (%headlist, @quickref, @saved_headers, %whitelist, @distributions, %mysql, %forbidden_crosspost, %scoreset, %maxscore);
our (@nomoderation, @htmlallowed, @htmltags, %extracontent, %forbidden_headers, @forbidden_groups,%dnsbl,@localip);

########
#
# style_filter(): check headers
#
#######

sub style_filter()
{
        my ($host, $time, $pid, $ip, $date, $client_dn, $length, $head_length, $md5, $domain, $gruppi, $followup) = &query_cache_header();

#######################
# Split Newsgroups and Followup-To
#######################

	my @gruppi   = split( /[, ]+/, $hdr{'Newsgroups'}  );
        my @followup = split( /[, ]+/, $hdr{'Followup-To'} );

#######################
# Control Messages
#######################

        if (
                (
                        (
                                ( $hdr{'Control'} ne "" ) and
                                ( $hdr{'Control'} !~ /^cancel\ /i )
                        ) or
                        (
                                ( $hdr{'Also-Control'} ne "" ) and
                                ( $hdr{'Also-Control'} !~ /^cancel\ /i )
                        )
                ) or
                (
                        ( $config{'allow_control_cancel'} eq "false" ) and
                        (
                                ( $hdr{'Control'} ne "" ) or
                                ( $hdr{'Also-Control'} ne "" )

                        )
                )
           )
        {
                 &log( "err", "Message includes an invalid Control header ($hdr{'Control'}), rejected" );
                 return 1;
        }

        if (
                ($config{'allow_supersedes'} eq "false") and
                (
                        ($hdr{'Supersedes'} ne "") or
                        ($hdr{'Cancel'} ne "") or
                        ($hdr{'Replaces'} ne "")
                )
           )
        {
                &log( "err", "Message includes an invalid Supersedes header ($hdr{'Supersedes'}), rejected" );
                return 51;
        }


#######################
# Forbidden Crosspost
#######################

        foreach ( keys %forbidden_crosspost )
        {
                if (
                        ( $hdr{'Newsgroups'} =~ /$forbidden_crosspost{$_}/i) and
                        ( $hdr{'Newsgroups'} =~ /$_/i )
                   )
                {
                        &log( "err", "Forbidden crosspost between $forbidden_crosspost{$_} and  $_, rejected" );
                        return 2;
                }

        }

#######################
# Approved Messages
#######################

        if ( $hdr{'Approved'} ne "" )
        {
                my $status = 0;

                foreach ( @nomoderation )
                {
                        if ( $hdr{'Newsgroups'} =~ /$_/i )
                        {
                                &log("notice", "Auto Approved message for $_ ($hdr{'Message-ID'}), accepted");
                                $status = 1;
                        }
                }
                if ( $status == 0 )
                {
                        &log( "err", "Message includes an hand made Approved header ($hdr{'Approved'}), rejected");
                        return 3;
                }
        }

#######################
# Distribution
#######################

        if (
                ( $config{'check_distribution'} eq "true" ) and
                ( $hdr{'Distribution'} ne "" )
           )
        {
                my $found = 0;

                foreach ( @distributions )
                {
                        $found = 1 if ($_ eq $hdr{'Distribution'});
                }

                if ( $found == 0 )
                {
                        &log( "err", "Message includes an invalid Distribution ($hdr{'Distribution'}), rejected" );
                        return 4;
                }
        }

#######################
# Content-Type
#######################

        foreach ( keys %extracontent )
        {
                if ( ($_ ne "") and ($extracontent{$_} ne "") and ($hdr{'Content-Type'} ne ""))
                {
                        if ( $hdr{'Newsgroups'} =~ /$_/i )
                        {
                                if ( $hdr{'Content-Type'} !~ /$extracontent{$_}/i )
                                {
                                        &log( "err", "Invalid Content-Type ($hdr{'Content-Type'}), rejected" );
                                        return 5;
                                }
                        }
                }
        }

#######################
# Maximum crosspost
#######################

        if ( @gruppi   > $config{'max_crosspost'}  )
        {
                &log( "err", "Message was sent to $gruppi groups, maximum is $config{'max_crosspost'}, rejected" );
                return 6;
        }

#######################
# Maximum followup
#######################

        if ( @followup > $config{'max_followup'} )
        {
                &log( "err", "Message was sent with $followup in f/up, maximum is $config{'max_followup'}, rejected" );
                return 7;
        }

        if (
                ( @gruppi    > $config{'max_fup_no_crsspt'} ) and
                ( @followup == 0 )
           )
        {
                &log( "err", "Message was sent to $gruppi groups and no followup was indicated; maximum is $config{'max_fup_no_crsspt'}, rejected" );
                return 8;
        }

#######################
# Article size
#######################

	if ( $length > $config{'max_body_size'} )
	{
		&log( "err", "Too long body ($length bytes, maximum is $config{'max_body_size'}, rejected" );
		return 9;
	}

        if ( $head_length > $config{'max_head_size'} )
        {
                &log( "err", "Too long headers ($head_length bytes, maximum is $config{'max_head_size'}, rejected" );
                return 23;
        }

	if ( ( $length + $head_length ) > $config{'max_total_size'} )
        {
                &log( "err", "Article too large, rejected" );
                return 57;
        }

#######################
# Groups difference
#######################

        if ( ($followup-$gruppi) > $config{'max_groups_difference'} )
        {
                &log( "err", "Too many groups in followup without enough crosspost, rejected");
                return 10;
        }

#######################
# Re: without references
#######################

        if (
                ( $hdr{'Subject'} =~ /^Re:\ /i ) and
                ( $hdr{'References'} eq "" )
           )
        {
                &log( "err",  "Subject starts with \"Re:\" and there are no references, rejected" );
                return 11;
        }

#######################
# Line counts
#######################

        my @body_strings = split( /\n/, $body );

        my ( $lines, $quoted, $oversized, $blank, $empty ) = 0;

        foreach ( @body_strings )
        {
                $quoted++
                if (
                        ( $_ =~ /^>/ ) or
                        ( $_ =~ /^:/ )
                   );

                $oversized++ if ( length($_) > $config{'max_line_length'} );
                $empty++     if ( $_ eq "\n" );
                $blank++     if ( $_ =~ /^\ +\n$/ );
                $lines++;
        }

        if ( $oversized > 0 )
        {
                &log( "err", "$oversized lines are longer than $config{'max_line_length'}, rejected" );
                return 12;
        }

        if ( $quoted    > $lines * $config{'max_quoted_ratio'} )
        {
                &log( "err", "Too many quoted lines ($quoted\/$lines), maximum rate is $config{'max_quoted_ratio'}, rejected" );
                return 13;
        }

        if ( $empty     > $lines * $config{'max_empty_ratio'}  )
        {
                &log( "err", "Too many empty lines ($empty\/$lines), maximum rate is $config{'max_empty_ratio'}, rejected" );
                return 14;
        }

        if ( $blank     > $lines * $config{'max_blank_ratio'}  )
        {
                &log( "err", "Too many blank lines ($blank\/$lines), maximum rate is $config{'max_blank_ratio'}, rejected" );
                return 15;
        }


#######################
# HTML tags
#######################

        my $stat = 0;

        foreach ( @htmlallowed )
        {
                $stat = 1 if ( $hdr{'Newsgroups'} =~ /$_/i );
        }

        if ( $stat == 0 )
        {
                foreach ( @htmltags )
                {
                        if ( $body =~ /$_/i )
                        {
                                &log( "err", "Message includes a forbidden HTML TAG ($_), rejected");
                                return 16;                              
                        }
                }
        }

#######################
# Unexistent groups
#######################

	if ( $config{'check_groups_existence'} eq "true" )
	{
        	foreach ( @gruppi )
        	{
			my $success = &check_group_existence($_);

                	if ( $success == 0 )
                	{
                        	&log( "err", "Message was sent to $_ that doesn't exist here, rejected" );
				$quickref[17] .= " ($_)";
                        	return 17;
                	}
        	}

        	foreach ( @followup )
        	{
			my $success = &check_group_existence($_);
                	if (
                        	( $success == 0 	) and
                        	( $_ ne "poster"    	) and
                        	( $_ ne "junk"      	)
                   	)
                	{
                        	&log( "err", "Message includes an invalid followup ($hdr{'Followup-To'}), rejected" );
                        	$quickref[18] .= " ($_)";
				return 18;
                	}
        	}
	}

#######################
# Date issues
#######################

        my $client_time = str2time( $hdr{'Date'} );
	$time 		= time(); 

	if ( $client_time > $time ) # message posted in the future
	{
		if ( ( $client_time - $time ) > $config{'max_grace_time'} )
		{
			my $diff_time = abs($client_time - $time);
                	&log( "err", "Article posted in the future (difference is $diff_time secs, maximum is $config{'max_grace_time'}), rejected" );
                	&log( "err", "Date: $hdr{'Date'}, real $hdr{'NNTP-Posting-Date'}, time $time/$client_time" );
                	return 19;
		} 
		else
		{
			my $diff_time = abs($client_time - $time);
			&log( "notice", "Article $hdr{'Message-ID'} posted in the future ($diff_time seconds), accepted" );
		}
	}
	else # message posted in the past
	{
		if ( ( $time - $client_time ) > $config{'too_old_limit'} )
		{
		        my $diff_time = abs($time - $client_time);
			&log( "err", "Article too old, $diff_time seconds, maximum $config{'too_old_limit'}, rejected" );
			&log( "err", "Date: $hdr{'Date'}, real $hdr{'NNTP-Posting-Date'}, time $time/$client_time" );
			return 58;
		}
	}

#######################
# Invalid Path
#######################

        if (
                ( $config{'force_valid_path'} eq "true" ) and
                (
                        ( index( $hdr{'Path'}, "!" ) != -1 ) or
                        ( $hdr{'Path'} =~ /\!.+\!/ ) 
                )
           )
        {
                &log( "err", "Invalid Path ($hdr{'Path'}), rejected" );
                return 20;
        }

#######################
# Headers oversize
#######################

	foreach ( keys %hdr )
	{
		if (length($hdr{$_}) > $config{'max_header_length'} )
		{
			&log( "err", "Header $_ is too long, rejected" );
			$quickref[21] .= " ($_)";
			return 21;
		}
	}


#######################
# Mail headers
#######################

        if (
                        ( $config{'allow_mail_headers'} eq "false" ) and
                        (
                                ( $hdr{'Received'}      ne "" ) or
                                ( $hdr{'To'}            ne "" ) or
                                ( $hdr{'CC'}            ne "" ) or
                                ( $hdr{'BCC'}           ne "" ) or
                                ( $hdr{'Delivered-to'}  ne "" )
                        )
                     )
        {
                &log( "err", "Forbidden email header, rejected" );
                return 22;
        }

#######################
# Forged In-Reply-To
#######################

        if (
                ( $hdr{'References'}  ne "" ) and
                ( $hdr{'In-Reply-To'} ne "" ) and
                ( index( $hdr{'References'}, $hdr{'In-Reply-To'} ) == -1 )
           )
        {
                &log( "err", "Invalid In-Reply-To ($hdr{'In-Reply-To'}), rejected" );
                return 24;
        }

#######################
# Hierarchy checks
#######################

        my ( $gerarchia, $gruppo, $risposte, @archivio, $numero );
        if ( $gruppi > 1 )
        {
                foreach ( @gruppi )
                {
                        ( $gerarchia, $gruppo ) = split( /\./, $_, 2 );

                        $numero = 0;
                        foreach ( @archivio )
                        {
                                $numero = 1 if ( $_ eq $gerarchia );
                        }
                        push( @archivio, $gerarchia ) if ( $numero == 0 );
                }
                my $hier_number = @archivio;

                if ( $hier_number > $config{'max_hierarchies_post'} )
                {
                        &log( "err", "Message was sent to $hier_number hierarchies, max is $config{'max_hierarchies_post'}, rejected" );
                        return 25;
                }
        }

        @archivio = undef;

        if ( $followup > 1 )
        {
                foreach ( @followup )
                {
                        ( $gerarchia, $gruppo ) = split( /\./, $_, 2 );

                        $numero = 0;
                        foreach ( @archivio )
                        {
                                $numero = 1 if ( $_ eq $gerarchia );
                        }
                        push( @archivio, $gerarchia ) if ( $numero == 0 );
                }
                my $hier_number = @archivio;
                if ( $hier_number > $config{'max_hierarchies_post'} )
                {
                        &log( "err", "Message was sent to $hier_number hierarchies in followup, max is $config{'max_hierarchies_post'}, rejected" );
                        return 26;
                }
        }

#######################
# Binary Contents (UUEncode)
#######################

	my $uuencode = &check_uuencode();
	if ($uuencode != 0) 
	{
		if ( 
			($config{'allow_uuencode'} eq "true")
		   )
		{
			&log( "notice", "Message includes UUEncoded body text but allow_uuencode is set to true" );
		}
		else
		{
			&log( "err", "Message includes in the body UUEncoded text, rejected");
			return $uuencode;
		}
	}

#######################
# Binary Contents (YENC)
#######################

        my $yenc = &check_yenc();
        if ($yenc != 0)
        {
                if (
                        ($config{'allow_yenc'} eq "true")
                   )
                {
                        &log( "notice", "Message includes YENC body text but allow_uuencode is set to true" );
                }
                else
                {
                        &log( "err", "Message includes in the body a text encoded with YENC, rejected");
                        return $yenc;
                }
        }

#######################
# Forbidden headers
#######################

        foreach ( keys %hdr )
        {
                my $header = $_;
                foreach ( keys %forbidden_headers )
                {
                        my $rule = $_;
                        my $exception = $forbidden_headers{$_};

                        if (
                                ( $header =~ /$rule/i ) and
                                ( $header !~ /$exception/i )
                           )
                        {
                                &log( "err", "Forged header $header matches $rule and not $exception, rejected" );
                                return 53;
                        }
                }
        }

#######################
# Forbidden groups
#######################

        foreach ( @forbidden_groups )
        {
                if (
                        ($hdr{'Newsgroups'}  =~ /$_/i) or
                        ($hdr{'Followup-To'} =~ /$_/i)
                   )
                {
                                &log( "err", "Message posted into $hdr{'Newsgroups'} or followup to $hdr{'Followup-To'} that is closed by $_, rejected" );
                                return 54;
                }
        }

        return 0;
}


########
#
# mod_headers(): Modify headers
#
#######

sub mod_headers()
{
        $modify_headers = 1;
	my ($host, $time, $pid, $ip, $date, $client_dn, $length, $head_length, $md5, $domain, $gruppi, $followup) = &query_cache_header();

#######################
# Organization
#######################

        $hdr{'Organization'} = $config{'organization'} if ( $config{'force_default_organization'} eq "true" );
       
#######################
# X-Trace
#######################

	&delete_headers("X-Trace") if ( $config{'delete_header_x-trace'} eq "true" );

#######################
# Cancel-Lock
#######################

	if ( $config{'add_cancel_lock'} eq "true" )
	{
		my $success;
		if ( $config{'lock_method'} eq "sha1" )
		{
			$success = &add_canlock( $config{'salt'} );
		}
		else
		{
			$success = &add_canlock( $config{'salt'}, 1 );
		}
	}

#######################
# Cancel-Key
#######################

	if (
		( $hdr{'Control'} =~ /^cancel\ /i ) or
		( $hdr{'Supersedes'} )
	   )
	{
		my ( $control_command, $target_mid );
		if ( $hdr{'Control'} =~ /^cancel\ /i )
		{
			( $control_command, $target_mid ) = split / /, $hdr{'Control'};
		}
		elsif ( $hdr{'Supersedes'} )
		{
			($target_mid) = $hdr{'Supersedes'};	
		}
		
		if ( $config{'lock_method'} eq "sha1" )
		{
			&add_cancelkey( $target_mid, $config{'salt'} );
		}
		else
		{
			&add_cancelkey( $target_mid, $config{'salt'}, 1 );
		}
	}

#######################
# Sender
#######################

        if ( $hdr{'Sender'} ne "" )
        {
                &delete_headers("Sender") if ( $config{'delete_header_sender'} eq "true" );
                if ( $config{'delete_header_sender'} eq "anon" )
                {
                        $hdr{'Sender'} = $user . "@" . $host;
                }
        }

#######################
# NNTP-Posting-Host
#######################

        if ( $hdr{'NNTP-Posting-Host'} ne "" )
        {
                &delete_headers("NNTP-Posting-Host") if ( $config{'delete_header_nntp-posting-host'} eq "true" );
                if ( $config{'delete_header_nntp-posting-host'} eq "anon" )
                {
                        my $ctx = Digest::MD5->new;

                        my $nph = $hdr{'NNTP-Posting-Host'} . $config{'salt'}; #tnx to marco d'itri
                        $ctx->add($nph);
                        my $md5_nph = $ctx->b64digest;
                        $hdr{'NNTP-Posting-Host'} = $md5_nph . ".user." . $host;
                }
        }

#######################
# NNTP-Posting-Date
#######################

        &delete_headers("NNTP-Posting-Date") if (
                                                 ( $config{'delete_header_nntp-posting-date'} eq "true" ) and
                                                 ( $hdr{'NNTP-Posting-Date'} ne "" )
                                              );

#######################
# Custom headers
#######################

        if ( $config{'delete_custom_headers'} eq "true" )
        {
                my @deleted_headers;
                my $header_key;
                my $status = 0;

		push(@saved_headers, "Cache" ); # save cache for further use

                foreach (keys %hdr)     # tnx to marco d'itri
                {
                        $header_key = $_;


                        $status = 0;

                        foreach ( @saved_headers )
                        {
                                $status = 1 if ( $_ eq $header_key );
                        }

                        if ( $status == 0 )
                        {
                                push(@deleted_headers, $header_key);
                        }
                }

                &delete_headers(@deleted_headers);

        }

#######################
# User-Agent
#######################

	&delete_headers("User-Agent", "X-Mailer", "X-Newsreader" ) if ( $config{'delete_header_user-agent'} eq "true" );

#######################
# Mail Headers
#######################

        &delete_headers("Received", "In-Reply-To", "Delivered-To", "BCC", "CC", "To" ) if ( $config{'delete_mail_headers'} eq "true" );

#######################
# X-No-Archive
#######################

	&delete_headers("X-No-Archive") if ( $config{'delete_header_x-no-archive'} eq "true" );

#######################
# New Headers
#######################

        if ( $config{'include_new_headers'} eq "true" )
        {
                foreach ( keys %headlist )
                {
                        $hdr{$_} = $headlist{$_};
                }

        }

        return  0;
}

########
#
# add_canlock(): Add Cancel-Lock header
#
#######

sub add_canlock($$)
{
	$modify_headers = 1;
	my ( $secret, $usemd5 ) = @_;
	my $lock;
	$secret || return undef;

        my $id = $hdr{'Message-ID'};
	&log( "debug", "Adding Cancel-Lock to $id" );

	if ($usemd5) 
	{
		$lock = 'md5:' . make_canlock_md5( $secret, $id );
	}
	else 
	{
		$lock = 'sha1:' . make_canlock_sha1( $secret, $id );
	}

	my $o = $hdr{'Cancel-Lock'};
	$hdr{'Cancel-Lock'} = ( $o ? "$o\n\t" : '' ) . $lock;

	return '';
}

########
#
# add_cancelkey(): Add Cancel-Key header
#
#######

sub add_cancelkey($$$)
{
	$modify_headers = 1;
	if ( !$hdr{'Cancel-Key'} ) 
	{
		my ( $tocancel, $secret, $usemd5 ) = @_;
		my ($key);
		&log( "debug", "Adding Cancel-Key for message $tocancel");
		$secret || return undef;

		if ($usemd5) 
		{
			$key = 'md5:' . make_key_md5( $secret, $tocancel );
		}
		else 
		{
			$key = 'sha1:' . make_key_sha1( $secret, $tocancel );
		}

		my $o = $hdr{'Cancel-Key'};
		$hdr{'Cancel-Key'} = ( $o ? "$o\n\t" : '' ) . $key;
	}
	return '';
}

########
#
# make_canlock_md5(): Generate Cancel-Lock value using md5
#
#######

sub make_canlock_md5($$)
{
	my ( $secret, $id ) = @_;
	my $hash = Digest->new('MD5');
	$hash->add( make_key_md5( $secret, $id ) );
	return $hash->b64digest . '==';

}

########
#
# make_canlock_sha1(): Generate Cancel-Lock value using sha1
#
#######

sub make_canlock_sha1($$)
{
	my ( $secret, $id ) = @_;
	my $hash = Digest->new('SHA-1');
	$hash->add( make_key_sha1( $secret, $id ) );
	return $hash->b64digest . '=';
}

########
#
# make_key_md5(): Generate Cancel-Key value using md5
#
#######

sub make_key_md5($$) 
{
	my ( $secret, $id ) = @_;
	my $hmac = Digest::HMAC->new( $secret, 'Digest::MD5' );
	$hmac->add($id);
	return $hmac->b64digest . '==';

}

########
#
# make_key_sha1(): Generate Cancel-Key value using sha1
#
#######

sub make_key_sha1($$)
{
	my ( $secret, $id ) = @_;
	my $hmac = Digest::HMAC->new( $secret, 'Digest::SHA1' );
	$hmac->add($id);
	return $hmac->b64digest . '=';
}




1;
