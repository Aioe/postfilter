# Copyright (c) 2005-2018, Paolo Amoroso (Aioe) <freedom@aioe.org>
# All rights reserved.
# Postfilter (checkconfig.pm) version 0.8.3

use strict;

our (%hdr, $dbh, @access, $modify_headers, $body, $user, %config, %public_rights_ip, %public_rights_domain, %auth_rights, %ban_limits);
our (%headlist, @quickref, @saved_headers, %whitelist, @distributions, %mysql, %forbidden_crosspost, %scoreset, %maxscore);
our (@nomoderation, @htmlallowed, @htmltags, %extracontent, %forbidden_headers, @forbidden_groups,%dnsbl,@localip);
our (%csyntax,@access_keys);

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

	&log("debug", "Checking whitelist syntax");

	foreach (keys %whitelist)
	{
		my $key = $_;
		my $regex = $whitelist{$key};
		my $success = eval { qr/$regex/i };
                unless($success)
                {
                	&log("err", "Syntax error in access.conf: whitelist: key $key requires a perl regexp, $regex is not valid");
                        return 93;
                }
	}

	foreach( @access_keys )
	{
		my $key = $_;

		if ($public_rights_ip{$key} == 0)
		{
			&log("err", "Syntax error in access.conf: \$public_rights_ip{$key} is missing");
			return 93;
		}

		if ($public_rights_domain{$key} == 0)
                { 
                        &log("err", "Syntax error in access.conf: \$public_rights_domain{$key} is missing");
                        return 93;
                }

		if ($auth_rights{$key} == 0)
                { 
                        &log("err", "Syntax error in access.conf: \$auth_rights{$key} is missing");
                        return 93;
                }
	}

	&log("debug", "Checking rules.conf syntax");

	my $success = &check_hash_syntax(%forbidden_crosspost);
	return $success if ($success != 0);

	$success = &check_hash_syntax(%extracontent);
        return $success if ($success != 0);	

	$success = &check_hash_syntax(%forbidden_headers);
	return $success if ($success != 0);

	$success = &check_array_syntax(@forbidden_groups);
	return $success if ($success != 0);

        $success = &check_array_syntax(@htmlallowed);
        return $success if ($success != 0);

	$success = &check_array_syntax(@htmltags);
        return $success if ($success != 0);

	return 0;
}

sub check_array_syntax()
{
	my @array = @_;

	foreach(@array)
	{
		my $value = $_;
		my $success = eval { qr/$value/i };
                unless($success)
                {
			&log("debug", "Array: $value");
                        &log("err",   "Syntax error in rules.conf: value $value is not a valid regexp");
                        return 94;
                }
	}
	return 0;
}

sub check_hash_syntax()
{
	my (%hash) = @_;

        foreach( keys %hash)
        {
                my $key = $_;
                my $value = $hash{$key};
		
		&log("debug", "Key $key => $value");

                my $success1 = eval { qr/$key/i };
		my $success2 = eval { qr/$value/i };
                unless($success1)
                {
                        &log("err", "Syntax error in rules.conf: key $key is not a valid regexp");
                        return 94;
                }

                unless($success2) 
                {
                        &log("err", "Syntax error in rules.conf: for key $key value $value is not a valid regexp");
                        return 94;
                }


        }

	return 0;
}



1;

