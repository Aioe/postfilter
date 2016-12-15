# Copyright (c) 2005-2009, Paolo Amoroso (Aioe) <freedom@aioe.org>
# All rights reserved.
# Postfilter (custom.pm) version 0.8.1

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
	
	if ( ($hdr{'Newsgroups'} =~ /\.net\-abuse\./i) and ( $hdr{'From'} =~ /Jamie.+darkshad/i) )
        {
                &log( "err", "Jamie strikes again" );
                $quickref[101] = "You're not welcome here, Jamie";
                return 101;
        }

        if ( ($hdr{'Newsgroups'} =~ /aioe\./i) and ( $hdr{'User-Agent'} =~ /newsportal/i) and ($body =~ /http\:\/\//i) )
        {
                &save_message();
                &log( "err", "Spambot against aioe.org");
                $quickref[102] = "You can't include URLs when you post through the WEB";
                return 102;
        }

	return 0;
}
