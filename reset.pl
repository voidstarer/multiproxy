#!/usr/bin/perl -w
use strict;
use DBI;
use DateTime;
use Switch;

my $db;
my $user;
my $pass;
my $instance;

sub read_db_connect_param
{
	open(FILE, "db_connect.txt") or die "Error: no db_connect.txt file found.";
	$db = <FILE>;
	$user = <FILE>;
	$pass = <FILE>;
	$instance = <FILE>;

	chomp($db);
	chomp($user);
	chomp($pass);
	chomp($instance);
}

sub do_log {
	my $message      = shift;
	my $time = localtime();
	return print "$time: reset.pl: $message\n";
}

read_db_connect_param();

do_log "Resetting";
my $dbh = DBI->connect($db,$user,$pass) or die "[".localtime()."] Connection Error: $DBI::errstr\n";
my $reset = "update mod_proxymngrtable set status=1 WHERE instance_id=$instance and status=0;";
do_log "Resetting status with: $reset";
$dbh->do($reset);

my $sql_access = "select mod_proxyauthorizeip.id, mod_proxyauthorizeip.client_ip, mod_proxyauthorizeip.action, mod_proxymngrtable.ip, mod_proxymngrtable.port, mod_proxymngrtable.id from mod_proxyauthorizeip, mod_proxymngrtable where mod_proxymngrtable.id = mod_proxyauthorizeip.port_id and mod_proxyauthorizeip.action = 1 and mod_proxyauthorizeip.operation = 0 and mod_proxymngrtable.instance_id = $instance";
do_log "Reset access with: $sql_access";
if ($dbh->do($sql_access) != 0){
        do_log "There are access to reset.";

	my $sth2 = $dbh->prepare($sql_access);
        $sth2->execute;

        while (my @row = $sth2->fetchrow_array) {
		my $sql_reset = "UPDATE mod_proxyauthorizeip SET operation=1 WHERE id=$row[0]";
        	do_log "Resetting: operation = 1 for id $row[0].";
		$dbh->do($sql_reset);
        }
}else{
        do_log "There are no access to reset.";
}

