0.7.7 -> 0.7.9

NEW:	A new installer is able to install postfilter without human work.

NEW:	Now postfilter is able to accept, reject or mark all articles that come from TOR. Old $config{'block_tor'} is
	replaced by $config{'tor_network'} -> [ "allow" | "reject" | "mark" ], If this is set to "mark", a special
	header X-TOR-Router is added and 'tor-network' is inserted inside the Path:

NEW:	Now Postfilter is able to detect whether INN 2.4 or 2.5 is running ($config{'version'} shows this)

NEW:	Three new modules (exit.pm that handles the exit logic, access.pm that includes all code about access rights,
	mysql.pm that handles mysql backend )

NEW:    Postfilter can be configured in order to skip URIBL.com or SURBL URIBL check

NEW:	A much better MySQL code (that correctly handles the errors)

NEW:	UUEncoded and encoded with YENC texts are separately handled. Now $config{'allow_yenc'} permits to allow only
	yenc texts.

NEW:	All features can be disabled in an explicit manner through $config{'check_*}

NEW:	X-No-Archive can be deleted ($config{'delete_header_x-no-archive'} set whether to keep or delete it)

NEW:	A new document explains how to delete an header inside a locally posted message.

NEW:    postfilter.conf and banlist.conf have got a man page

BUGFIX: postfilter.pl, modules/style.pm, modules/rbl.pm, modules/other.pm, modules/access.pm, modules/custom.pm are fully commented
BUGFIX: Postfilter now uses INN::Syslog instead of Sys::Syslog
BUGFIX: Now messages that come from stdin (if nnrpd is invoked through command line) are correctly handled
BUGFIX: Postfilter skips TOR checks if an article comes from stdin or localhost, URIBL checks are skipped if no URI are
	found inside the body
BUGFIX: if custom rules return a code that hasn't got a corresponding error string, a message is printed in the logs and that article is
	rejected with a generic rejection string ($quickref[63]).
BUGFIX: if postfilter is linked to the wrong nnrpd perl filter file (nnrpd_*.pl inside pathfilter), now an error is printed
	in the logs (news.crit) and an human readable error message is sent to the remote client.
BUGFIX: Removed 'hidden' User-Agent because now user agent related headers can be deleted. Added a new subroutines that works
	both with inn 2.4 and 2.5
BUGFIX: Now *all* regular expressions are case insensitive
BUGFIX: access.pm works much better, check per domain can be disabled.

0.7.6 -> 0.7.7

New:	Postfilter doesn't need Mail::RBL no more. For each DNSBL, it's possible to define which return codes (127.0.0.*)
	must be considered errors

New:	Postfilter supports SURBL and URIBL.com URIBLs if $config{'check_uribl'} is set to true.

BUGFIX:	Removed $config{'allow_useless_followup'} that is useless since many newsreaders (like knode) add the same groups
	to Newsgroups and Followup-To

BUGFIX: Now it's possible to set a maximum size for each article (headers + body), body, all headers and each single header
BUGFIX: Now articles with past or future dates are separately handled in a much better way.
BUGFIX: Removed $config{'check_sender'} that was useless and breaks the USEFOR draft

0.7.5 -> 0.7.6

BUGFIX: When an article is rejected due the banlist, now postfilter logs which banlist rule matches the current message
	in news.err instead of news.notice.

BUGFIX: $config{'force_valid_path'} now rejects only those articles with a preloaded path.

NEW:	the old postfilter.pl is now split among various files inside modules/ This makes easier to read the code.

NEW:	Now postfilter is able to generate Cancel-Lock and Cancel-Key

NEW:	Postfilter supports DNSRBL (if $config{'check_rbl'} is set to "true" the @dnsbl array in postingrules.conf defines which
	DNSRBL must be queried. Beware: it's a slow process.

NEW:	Postfilter allows the users to build their own rules in modules/custom.pm These rules *can* use all variables and all
	subroutines used by postfilter. This check affects also whitelisted messages.

NEW:	A new - much better - way to ban TOR exit nodes. postfilter-tor.pl was removed. Those who make use of this feature must
	fill @localip (inside postingrules.conf) with *all* ip addresses used by he server.

0.7.4 -> 0.7.5

BUGFIX: now if legal.log can't be opened, postfilter returns an human readable error instead of '44'
BUGFIX: removed 'simple' filter status because useless
BUGFIX: now postfilter rejectes all messages if there's an error in a *configuration* file.
BUGFIX: The banlist is now able to properly send emails (send:email:email@address.tld:)
BUGFIX: If innconfval is used, values set by innconfval are *not* replaced with those inside postingrules.conf

NEW:	The original postfilter.conf is now split into three file (postfilter.conf for general 
	configurations, postingaccess.conf for users' access rights and postingrules.conf for other
	minor configuration parameters).

NEW:	A new, better and completely rewised logging system is now available. New logs are more accurate,
	use different logging levels (debug, notice, err and crit) and everything is logged.

NEW:	Now it's possible to configure which number of articles with the same MD5 hash (idest multipost)
	must be accepted by postfilter. An article will be rejected as duplicate only if posfilter finds
	*more* than $config{'maximum_multipost'} articles with the same md5.

NEW:	It's possible to set a separate maximum allowed multipost per IP, domain or UserID through
	postingaccess.conf. Each value must be lower than the one set by $config{'maximum_multipost'}.

NEW:	Which criteria have to be used by postfilter in order to calaculate the MD5 hash needed to detect
	multipost is now configurable (through $config{'md5_hash'})

NEW:	The syslog facility used by postfilter is now configurable through $config{'syslog_facility'}, 
	extra logs (in [syslog_facility].debug) can be turned on setting $config{'verbose_log'} to "true"

NEW:	Now it's possible to close a group without using the banlist. This is done by @forbidden_groups
	that is inside postingaccess.conf.

0.7.3 -> 0.7.4

NEW:    some group that needs auto-approved messages (notably alt.sysadmin.recovery) is now supported.
	@nomoderation sets which groups have got this (strange) rule.

NEW:    Allowed Content-Types can be configured *per* group. (%extracontent does this) By default, only
        "text/plain" is allowed for all (only control.* has got own rules).

NEW:    HTML Tags can be configured (@htmltags) and some group can be excluded by this check (@htmlallowed
	does this).

NEW:	There's a way to avoid forgeries of system headers. %forbidden_headers does this (key sets a rule,
	value the only allowed exceptions).

BUGFIX: Now Control cancels and Supersedes are separately handled.

BUGFIX: MD5 hash of each article now includes also Subject and Newsgroups. This should solve a Thunderbird
	issue when an user tries to send a cancel (if cancels are accepted).

BUGFIX: Now UUEncoded binaries can be rejected if $config{'allow_uuencode'} is set to "false". Before this,
	the only way to ban UUEncode was through the banlist 

BUGFIX: Removed src/modfilter.pl that is available as separate package (see ftp://ftp.aioe.org/)

0.7.2 -> 0.7.3

BUGFIX:	'delete $hdr{'Header'};' instead of '$hdr{'Header'} = undef;'
BUGFIX: now the behaviour of postfilter when an error is found inside banlist.conf is configurable
NEW: 	The maximum difference between the number of groups in Followup-To and in Newsgroups can be set
NEW:	Articles that include the same groups inside Newsgroups: and Followup-To: now can be rejected
NEW: 	Articles that come from TOR exit nodes can be filtered. An external program shipped with postfilter 
	- postfilter-tor.pl - is able to build a list of all working exit nodes.
NEW:	Added a new tool - postfilter-legal.pl - that is able to query and expire legal.log
	
0.7.1 -> 0.7.2 

NEW: 	A completely revised banlist with more features
NEW: 	A better documentation
