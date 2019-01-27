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

	return 0;
#######################################################################################################################################

}

1;

