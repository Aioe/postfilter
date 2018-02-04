# Copyright (c) 2005-2010, Paolo Amoroso (Aioe) <freedom@aioe.org>
# All rights reserved.
# Postfilter (custom.pm) version 0.8.2

use Date::Parse;
use Digest;
use strict;

our (%hdr,  @access, $dbh, $modify_headers, $body, $user, %config, %public_rights_ip, %public_rights_domain, %auth_rights, %ban_limits);
our (%headlist, @quickref, @saved_headers, %whitelist, @distributions, %mysql, %forbidden_crosspost, %scoreset, %maxscore);
our (@nomoderation, @htmlallowed, @htmltags, %extracontent, %forbidden_headers, @forbidden_groups,%dnsbl);

########
#
# custom_rules(): Customized rules should be inserted here
#
#######

sub custom_rules()
{
	my ($host, $time, $pid, $ip, $date, $client_dn, $length, $head_length, $md5, $domain, $gruppi, $followup) = &query_cache_header();


###############################################################################################################################################

        if ($hdr{'X-Server-Commands'} =~ /forcerejection/i )
	{
		&log("err", "Message rejected due sender request");
		return 91;
	}
	

######################################################################################################################################


        if ( ($hdr{'Newsgroups'} =~ /aioe\./i) and ( $hdr{'User-Agent'} =~ /newsportal/i) and ($body =~ /http\:\/\//i) )
        {
                &save_message();
                &log( "err", "Spambot against aioe.org");
                $quickref[102] = "You can't include URLs when you post through the WEB";
                return 102;
        }


######################################################################################################################################


	my @headers_to_check = ( "From", "Newsgroups", "Followup-To", "Path" );


	foreach( @headers_to_check )
	{
		my $result = &check_unknownchars($_);
		return $result if ($result != 0);
	}

######################################################################################################################################

        if ($hdr{'Newsgroups'} =~ /it\.hobby\.elettronica/i)
        {
#                my $res = &checkuserdb("it.hobby.elettronica");
#                return $res if ($res != 0);
        }

#######################################################################################################################################

	if ($hdr{'Newsgroups'} =~ /it\.comp\.hardware/i)
	{
		if ($body =~ /amzm\.to/im)
		{
			$quickref[107] = "Amazon links are forbidden inside it.comp.hardware";
			return 107;
		}		
	}

#######################################################################################################################################

	if ($hdr{'References'} ne "")
	{
		my $refers = $hdr{'References'};
		my @references = split(/\</, $refers);
		my $lastref = "<" . $references[-1];	# estrae l'ultima referenza

		my $fate = &check_localdistribution($lastref);
		
		if ($fate == 1)  # se il messaggio è una risposta ad un messaggio che contiene Distribution: local
		{
			if ($hdr{'Distribution'} !~ /usenet|local/)	
			{
				&log("notice", "This message is a reply to a local message ($lastref)");
				&log("notice", "Local message");
				$hdr{'Distribution'} = "local";
				my $exit = &save_localdistribution($hdr{'Message-ID'});
				return $exit if ($exit != 0);
			}		
		}
	
	}
	
        if ($hdr{'Distribution'} ne "" )
        {
                if ($hdr{'Distribution'} =~ /^local$/i )
                {
                        &log("notice", "Message with LOCAL Distribution");
                        &log("notice", "Local message");
                        my $fate = &save_localdistribution($hdr{'Message-ID'});
                        return $fate if ($fate != 0);
                }
                elsif ($hdr{'Distribution'} =~ /^usenet$/i )
                {
                        &log("notice", "Message includes USENET Distribution");
                        &delete_headers("Distribution")
                }
                else
                {
                        my $dist = $hdr{'Distribution'};
                        $quickref[108] = "Invalid Distribution ($dist)";
                        return 108;
                }
        }

##############################################################################################################################

	if (
		($hdr{'X-Newsreader'} =~ /PiaoHong\.Usenet\.Client\.Free\:1.65/i ) and
		($hdr{'Newsgroups'} =~ /aioe\.news\.assistenza/)
	   )
	{
		$quickref[109] = "Generic server failure";
		return 109;
	}


##############################################################################################################################

	my @closed_subnets = ( "151.66");

	my $forgroups = "it\.hobby\.fai\-da\-te|it\.diritto|it\.hobby\.viaggi|it\.tlc\.cellulari\.android";

	if ( $hdr{'Newsgroups'} =~ /$forgroups/i )
	{
	
		foreach (@closed_subnets)
		{
			if ( $ip =~ /^$_/ )
			{
				&log("err", "Message sent by $ip that matches $_" );
				$quickref[110] = "Closed subnet ($_)";
				if ( $hdr{'From'} !~ /franzgol\@N0SPAMtin\.it/i)
				{
					return 110;
				}
			}
		}
	}

	return 0;
}


sub checkuserdb()
{
	my $grouptocheck = shift(@_);

	&log("notice", "Message sent to a group ($grouptocheck) protected by userdb");

        my $FILEID;
        my $fileid = "/etc/news/postfilter/userdb/$grouptocheck.dat";

        $quickref[105] = "Unable to load $fileid";
        
	open $FILEID, "$fileid" or return 105;
        my @fromlist = <$FILEID>;
        close $FILEID;

        foreach (@fromlist)
        {
	        my $ffff = $hdr{'From'};
                my $gggg = $_;
                chop($gggg);
                if ($gggg eq $ffff)
                {
        	        &log("notice", "Article sent by a known user: $gggg");
                        return 0;       
                }
	}
        
	$quickref[106] = "Non puoi postare su $grouptocheck, contatta usenet\@aioe.org";
        my $ffgg = $hdr{'From'};

        &log("err", "Message sent by an unknown user: $ffgg");

        return 106;
}


sub save_localdistribution()
{
        my $mid = shift(@_);
        my $news_spool = "/var/spool/news/postfilter/localdistribution.dat";
        my $expire_time = 86400 * 90;
        my $current_time = time();

	$quickref[107] = "Unable to write $news_spool";

        if (open(FILE, "$news_spool"))
        {
                my @lines = <FILE>;
                close FILE;

                if (open(FILE, ">", $news_spool))
                {
                
                        foreach(@lines)
                        {
                                my ($epoch,$oldmid) = split(/\t/, $_);
                                print FILE "$epoch\t$oldmid" if ( $epoch > $current_time - $expire_time );
                        }
                                
                        print FILE "$current_time\t$mid\n";
                        close FILE;             
                } else {
                        &log("err", "Impossibile scrivere su $news_spool");       
                        return 107;
                }
        } else {
                &log("err", "Impossibile aprire $news_spool");
                return 107;
        }

        return 0;
}


sub check_localdistribution()
{
        my $mid = shift(@_);
        my $news_spool = "/var/spool/news/postfilter/localdistribution.dat";

        $quickref[107] = "Unable to write $news_spool";

        if (open(FILE, "$news_spool"))
        {
                my @lines = <FILE>;
                close FILE;

                foreach(@lines)
                {
                                my ($epoch,$oldmid) = split(/\t/, $_);
				chop $oldmid;
				return 1 if ($mid eq $oldmid);
                }
        } else {
                &log("err", "Impossibile aprire $news_spool");
                return 107;
        }

        return 0;
}

sub check_unknownchars()
{
	my $head = shift(@_);
 	my $string = $hdr{$head};
        my $DDposition = 1;   # conta l'ennesimo carattere quindi parte da uno

        my @ASCII = unpack("C*", $string);

	&log("debug", "Checking header $head againt invalid chars");

        foreach (@ASCII)
        {
                if (
                        (( $_ >= 32 ) && ( $_ <=  90 )) or
                        (( $_ >= 94 ) && ( $_ <= 126 )) or
                        ( $_ == 195 ) or
			( $_ == 185 ) or
			( $_ == 178 )
                   )
                {
                        $DDposition++;
                }
                else
                {
                        $quickref[104] = "Forbidden ($DDposition th) char (ASCII $_) inside $head";
			&log("err", "Header: $head\: $string .. Invalid $DDposition th char ASCII $_");
                        return 104;
                }
        }

	return 0;
}
