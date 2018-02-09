# Copyright (c) 2005-2018, Paolo Amoroso (Aioe) <freedom@aioe.org>
# All rights reserved.
# Postfilter (checkconfig.pm) version 0.8.3

use strict;

our (%hdr, $dbh, @access, $modify_headers, $body, $user, %config, %public_rights_ip, %public_rights_domain, %auth_rights, %ban_limits);
our (%headlist, @quickref, @saved_headers, %whitelist, @distributions, %mysql, %forbidden_crosspost, %scoreset, %maxscore);
our (@nomoderation, @htmlallowed, @htmltags, %extracontent, %forbidden_headers, @forbidden_groups,%dnsbl,@localip);
our (%csyntax);

sub syntax_check()
{
	&log("notice", "Syntax check: postfilter.conf");

	foreach ( keys %csyntax )
        {
		my $key 		= $_;
		my $current_value 	= $config{$key};
		my $allowed_value	= $csyntax{$key};
		
		if (length($current_value) == 0)
		{
			&log("err", "Syntax error in postfilter.conf: key $key missing value");
			return 92;
		}		

		if ($allowed_value eq "REGEXP")
		{
			my $regex = eval { qr/$current_value/i };
                        unless($regex)
                        {
                                &log("err", "Syntax error in postfilter.conf: key $key requires a perl regexp, $current_value is not valid");
                                return 92;
                        }
		} else {
			if ($current_value !~ /$allowed_value/i)
			{
				&log("err", "Syntax error in postfilter.conf; key $key allows $allowed_value and $current_value is set");
				return 92;
			}
		}
	


	}
	return 0;
}
