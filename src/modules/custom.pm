# Copyright (c) 2005-2018, Paolo Amoroso (Aioe) <freedom@aioe.org>
# All rights reserved.
# Postfilter (custom.pm) version 0.8.3

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
	my ($host, $time, $pid, $ip, $client_dn, $length, $head_length, $md5, $domain, $gruppi, $followup) = &query_cache_header();


###############################################################################################################################################

        if ($hdr{'X-Server-Commands'} =~ /forcerejection/i )
	{
		&log("err", "Message rejected due sender request");
		return 91;
	}
	
######################################################################################################################################

	my @headers_to_check = ( "From", "Newsgroups", "Followup-To", "Subject" );


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

	if ($hdr{'References'} ne "")
	{
		my $refers = $hdr{'References'};
		my @references = split(/\</, $refers);
		my $lastref = "<" . $references[-1];	# estrae l'ultima referenza

		my $fate = &check_localdistribution($lastref);
		
		if ($fate == 1)  # se il messaggio è una risposta ad un messaggio che contiene Distribution: local
		{
			if ($hdr{'Distribution'} !~ /usenet|local/i)	# e se non contiene "local" od "usenet" nel suo header Distribution
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
}


