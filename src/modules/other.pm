# Copyright (c) 2005-2018, Paolo Amoroso (Aioe) <freedom@aioe.org>
# All rights reserved.
# Postfilter (other.pm) version 0.8.3

use Date::Parse;
use Digest::MD5;
use Digest::SHA1;
use Digest;
use strict;

our (%hdr, $dbh, @access, $modify_headers, $body, $user, %config, %public_rights_ip, %public_rights_domain, %auth_rights, %ban_limits);
our (%headlist, @quickref, @saved_headers, %whitelist, @distributions, %mysql, %forbidden_crosspost, %scoreset, %maxscore);
our (@nomoderation, @htmlallowed, @htmltags, %extracontent, %forbidden_headers, @forbidden_groups,%dnsbl,@localip,%attributes);

########
#
# create_cache_header(): Create header Cache
#
#######


sub create_cache_header()
{

	my ( $host, $time, $pid, $ip, $date, $client_dn );

	if (($config{'version'} eq "2.4") or ($config{'version'} eq "2.5"))
	{
        	( $host, $time, $pid, $ip, $date ) = split( /\ /, $hdr{'X-Trace'}, 5 );
		$ip = "127.0.0.1" if ( $ip =~ /\:\:1/ ); # This will be removed as soon as IPv6 support will become stable
        	$client_dn = $hdr{'NNTP-Posting-Host'};
	} else {

		$time = time();
		$client_dn = $attributes{'hostname'};
		$ip = $attributes{'ipaddress'};
		$host = $attributes{'interface'};
		$date = $hdr{'Injection-Date'};
		$pid = 999; #fixme
	}


########################
# Body Length
########################

        my $length = length($body);

########################
# Headers Length
########################

        my $temp_headers = "";

        foreach ( keys %hdr )
        {
		$temp_headers .= "$_\: $hdr{$_}\n";
        }

        my $head_length = length( $temp_headers );

########################
# Article MD5
########################

        my $md5article;

        if ( $config{'md5_hash'} eq "body" )
        {
                $md5article = $body;
        }
        elsif ( $config{'md5_hash'} eq "simple" )
        {
                $md5article = "Subject: $hdr{'Subject'}\n\n" . $body;
        }
        elsif ( $config{'md5_hash'} eq "complex" )
        {
                $md5article = "Newsgroups: $hdr{'Newsgroups'}\n" . "Subject: $hdr{'Subject'}\n\n" . $body;
        }
        elsif ( $config{'md5_hash'} eq "all" )
        {
                $md5article = "Newsgroups: $hdr{'Newsgroups'}\n" . "From: $hdr{'From'}\n" . "Followup-To: $hdr{'Followup-To'}\n" . "Subject: $hdr{'Subject'}\n\n" . $body;
        }
        else
        {
                &log( "err", "Invalid criteria ($config{'md5_hash'}) for MD5 hash, using \"body\" ");
                $md5article = $body;
        }

        my $md5 = &create_md5($md5article);

########################
# Client's domain
########################

        my $domain = "";
        my @temp_domain = split( /\./, $client_dn );

        my $dots = 0;

        while ( $client_dn =~ /\./g )                    # debug
        {
                $dots++;
        }

	
        if ( $dots > 1 )                                        # se ci sono almeno due punti (e quindi TRE domini) ne
        {                                                       # togle uno, altrimenti copia l'host in domain
                shift( @temp_domain ) if ( $ip ne $client_dn ); # se e' un dominio cancella la parte a sinistra
                pop  ( @temp_domain ) if ( $ip eq $client_dn ); # se e' un ip elimina la parte a destra

                for ( my $n = 0; $temp_domain[$n] ne ""; $n++ )
                {
                        $domain .= $temp_domain[$n] . ".";
                }

                chop $domain;
        }
        else
        {
                $domain = $client_dn;
        }

########################
# Crosspost & Followup
########################

        my @gruppi   = split( /[, ]+/, $hdr{'Newsgroups'}  );
        my @followup = split( /[, ]+/, $hdr{'Followup-To'} );

        my $gruppi = @gruppi;
        my $followup = @followup;

        $modify_headers = 1;
        $hdr{'Cache'} = "$host $time $pid $ip $client_dn $length $head_length $md5 $domain $gruppi $followup";


        return 0;
}

########
#
# query_cache_header(): Query header Cache
#
#######

sub query_cache_header()
{
        my $text = $hdr{'Cache'};
        my @data = split( /\ /, $text );
        return @data;
}

########
#
# delete_cache_header(): Delete header Cache
#
#######

sub delete_cache_header()
{
	$modify_headers = 1;
	&delete_headers('Cache');
	return 0;
}

########
#
# save_message(): Save a message in a file
#
#######

sub save_message()
{
        my ($host, $time, $pid, $ip, $client_dn, $length, $head_length, $md5, $domain, $gruppi, $followup) = &query_cache_header();

        my $file_name;

########################
# Filename
########################

        if ( $hdr{'X-Postfilter-Error'} ne "" )
        {
                $file_name = sprintf( "%02d\.%d", $hdr{'X-Postfilter-Error'}, $time );
        }
        else
        {
                $file_name = "00" . "." . $time;
        }

########################
# File Path
########################

        my $file_path = $config{'dir_spool'} . "/" . $file_name;

        &log( "notice", "Saving $hdr{'Message-ID'} into $file_path" );

########################
# Save
########################

        open my $SAVE, ">$file_path";
        if (!$SAVE)
        {
                &log( "err", "Unable to save message into $file_path" );
                return( 41 );
        }

        foreach (keys %hdr)
        {
                print $SAVE "$_: $hdr{$_}\n";
        }

        print $SAVE "\n$body\n.\n";
        close $SAVE;
        return 0;
}

########
#
# custom_filter(): Run custom rules (custom.pm)
#
#######

sub custom_filter()
{
	my $error_code;

########################
# Run customized rules
########################

	eval { $error_code = &custom_rules() };
	
	if ($@)
	{
		&log( "err", "Unable to execute custom rules: $@" );
		return 0;
	}

########################
# Errors handling
########################

	if ($error_code =~ /^[0-9]+/)
	{
		if ($quickref[$error_code] ne "" )
		{
			return $error_code;
		}		
		else
		{
			&log("err", "Custom rule returns $error_code and the corresponding error string is black (\'$quickref[$error_code]\': user will receive a generic return string");
			$quickref[$error_code] = $quickref[63];
			return $error_code;
		}
	}
	else
	{
		&log( "err", "Custom rules return a bad value: \'$error_code\' instead of a number, message accepted" ); 
		return 0;
	}

	return 0;
}

########
#
# create_md5(): Create MD5 sign of a string
#
#######

sub create_md5($)
{
	my $text = $_[0];
        my $ctx = Digest::MD5->new;
        $ctx->add($text);
        my $md5 = $ctx->b64digest;
	return $md5;
}

########
#
# check_uuencode(): Check whether an article include UUEncoded text
# 
#######


sub check_uuencode()
{
	my @body = split(/\n/, $body );
        my $stat = 0;
        foreach ( @body )
        {
 	       $stat = 1 if ($_ =~ /^begin\ [0-9][0-9][0-9]/i  );
               $stat = 2 if (($_ =~ /^end/i) and ( $stat == 1 ));
        }

	if ( $stat == 2 )
        {
                return 52;
        }
	return (0);
}

########
#
# check_yenc(): Check whether an article include Yenc text
#
#######


sub check_yenc()
{
        my @body = split(/\n/, $body );
        my $stat = 0;
        foreach ( @body )
        {
               $stat = 1 if ($_ =~ /^\=ybegin\ /i);
               $stat = 2 if (($_ =~ /^\=yend/i) and ( $stat == 1 ));
        }

        if ( $stat == 2 )
        {
                return 62;
        }
        return (0);
}

########
#
# delete_headers(@headers_to_delete): Delete one o more headers
#
#######


sub delete_headers($)
{
        $modify_headers = 1;
        my @headers = @_;
        my $system_headers =    "^Path|^From|^Newsgroups|^Subject|^Control|^Supersedes|" .
                                "^Followup\-To|^Date|^Organization|^Lines|^Sender|^Approved|^Distribution|" .
                                "^Expires|^Message\-ID|^References|^Reply\-To|^NNTP\-Posting\-Host|" .
                                "^Mime\-Version|^Content\-Type|^Content\-Transfer\-Encoding|^X\-Trace|" .
                                "^X\-Complaints\-To|^NNTP\-Posting\-Date|^Xref|^Injector\-Info|^Summary|" .
                                "^Keywords|^Date\-Received|^Received|^Posted|^Posting\-Version|" .
                                "^Relay\-Version|^Bcc|^To|^CC";

        foreach ( @headers )
        {
                if ( $hdr{$_} ne "" )  # check whether that header exists
                {

########################
# Delete headers with 2.4
########################

                        if ( $config{'version'} eq "2.4" )
                        {
                                if ( $_ =~ /$system_headers/i )
                                {
                                        $hdr{$_} = undef;
                                        &log( "debug", "System header $_ set to undef" );
                                }
                                else
                                {
                                        delete $hdr{$_};
                                        &log( "debug", "Optional header $_ deleted" );
                                }
                        }

########################
# Delete headers with 2.5 or 2.6
########################
                        else
                        { 
                                $hdr{$_} = undef;
                        }
                }
                else
                {
                        &log( "debug", "Detected an attempt to delete $_ that doesn't exist" );
                }

        }
}


########
#
# read_active(): Read active file
#
#######

sub read_active()
{
	open my $ACTIVE, "$config{'file_active'}";
        if (!$ACTIVE)
        {
                &log( "err", "Unable to read data from $config{'file_active'}" );
                return 37;
        }
        my @active = <$ACTIVE>;
        close $ACTIVE;

	return @active;
}

########
#
# check_group_existence($group): Check whether a group exists
#
#######

sub check_group_existence($)
{
	my $group = $_[0];

	my @active = &read_active();

	foreach ( @active )
        {
        	my ($group_string, $first, $last, $type) = split( /\ /, $_ );
                return 1 if ( $group_string eq $group );
        }

	return 0;

}

	
1;
