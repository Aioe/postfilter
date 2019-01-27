#!/usr/bin/perl

use strict;

my $file = "/home/aioe/postfilter/etc/postfilter.conf";
my $art;

open FILE, "$file";

while ( my $line = <FILE> )
{
	$art .= $line;
}

print <<EOF;

.TH postfilter.conf 5 "May 3, 2019" "" "Postfilter main configuration file"

.SH NAME
postfilter.conf \- Postfilter main configuration file

.SH DESCRIPTION

postfilter.conf is the main postfilter configuration file. This file includes all the most important settings and
.B must be properly configured
before starting to use postfilter. The default values are set in order to provide the highest antispam and anti-abuse protection even if they 
are probably too restrictive for sites that use some sort of users authentication. Servers that offer unauthenticated access can use them as
they are.
.br
.B Beware:
configuration arguments are
.B case sensitive
so 'TRUE' and 'true' are 
.B not
the same. All postfilter configuration values 
.B must be
typed using only
.B minuscule letters.
In order to avoid strange and hard to predict behaviours, it's higly recommended to assign a value to all configuration directives that are stored 
inside
postfilter.conf. Deletion of configuration keys should be avoided. 

.SH List of all variables
.P
The following variables can be configured through postfilter.conf:
.P
.td

EOF

my $num = 0;

while ( $art =~ /\n\#\n\#(.+)\n\#\n/g )
{
	$num++;
	my $line = $1;
	$line =~ /\ (.+) \-\>(.+)/;
	my $command = $1;
	my $values  = $2;

	my $lung = length($command);

	my $spaces = 42 - $lung;

	my $numero;

	if ( $num < 10 )
	{
		$numero = "0$num";
	}
	else
	{
		$numero = $num;
	}

	print ".B $numero.\n$command";
	
	for ( $spaces; $spaces > 0; $spaces-- )
	{
		print " ";	
	}

	$values =~ s/\"/\'/g;
	
	print "$values\n.br\n";
}

print ".SH OPTIONS\n.P\n";

open FILE, "$file";
my @lines = <FILE>;

$num = 0;

foreach (@lines)
{
  	if ( $_ =~ /^#\ ([a-zA-Z].+)\n/ )
	{ 
		my $pd = $1; 
                $pd =~ s/\"/\'/g;
		print "$pd\n"; 
	}

	if ( $_ =~ /^#\n\#/ )
	{
		print "\n";
	}

	if ( $_ =~ /\#\ \$config.+\-\>/ )
	{
		$num++;
		$_ =~ /\#\ (.+)\n/;
	        my $pd = $1;
		$pd =~ s/\"/\'/g;
		print "\n.br\n.B $num. $pd\n.br\n.P\n";
	}

}

print <<EOT;

.SH NOTES

Even if it's used like a configuration file, 
.B postfilter.conf
is still a perl script that must follow 
.B all perl syntax rules.
The easiest way to check whether postfilter.conf follows the perl syntax is through the perl command:
.br
.P
.B # perl -wc postfilter.conf
.br
.P
Postfilter has got a built-in check that 
.B rejects all incoming messages
if postfilter.conf includes some syntax error. This is a security feature and it's designed to prevent the postfilter users from accepting unwanted 
articles due configuration errors. 
.P
It's important to remember that postfilter.conf like all other perl modules
.B must
end with a costant positive value like the following: 
.br
.P
.B 1;
.br
.P
This file also needs to be readable by the same system user that executes nnrpd, usually news. Postfilter doesn't write data into postfilter.conf.

.SH AUTHOR

Paolo Amoroso \<freedom\@aioe.org\>

EOT
