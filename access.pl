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
	return print "$time: access.pl: $message\n";
}

read_db_connect_param();

my $dbh = DBI->connect($db,$user,$pass) or die "[".localtime()."] Connection Error: $DBI::errstr\n";

my $sql_kill = "select mod_proxyauthorizeip.id, mod_proxyauthorizeip.client_ip, mod_proxyauthorizeip.action, mod_proxymngrtable.ip, mod_proxymngrtable.port, mod_proxymngrtable.id from mod_proxyauthorizeip, mod_proxymngrtable where mod_proxymngrtable.id = mod_proxyauthorizeip.port_id and mod_proxyauthorizeip.action = 2 and mod_proxyauthorizeip.operation = 1 and mod_proxymngrtable.instance_id = $instance";
if ($dbh->do($sql_kill) != 0){
        do_log "There are ports to remove.";

        my $sth = $dbh->prepare($sql_kill);
        $sth->execute;

        while (my @row = $sth->fetchrow_array) {
		my $sql_removed = "UPDATE mod_proxyauthorizeip SET operation=0 WHERE id=$row[0]";
        	do_log "Removing access to ip $row[1] for port $row[4].";
                if ($row[3] eq "0.0.0.0"){
			system("iptables -D INPUT -p tcp -s $row[1] --dport $row[4] -j ACCEPT\n");
		}else{
			system("iptables -D INPUT -p tcp -s $row[1] -d $row[3] --dport $row[4] -j ACCEPT\n");
		}
		$dbh->do($sql_removed);

		#my $time_rem = localtime();
		#my $sql_log_rem = "INSERT INTO proxymng_status (id, client_ip, backend_ip, backend_port, date, enabled) VALUES($row[5], '$row[1]', '$row[3]', '$row[4]', '$time_rem', 0)";
		#$dbh->do($sql_log_rem);
        }
}else{
        do_log "There are no access to remove.";
}

my $sql_add = "select mod_proxyauthorizeip.id, mod_proxyauthorizeip.client_ip, mod_proxyauthorizeip.action, mod_proxymngrtable.ip, mod_proxymngrtable.port, mod_proxymngrtable.id from mod_proxyauthorizeip, mod_proxymngrtable where mod_proxymngrtable.id = mod_proxyauthorizeip.port_id and mod_proxyauthorizeip.action = 1 and mod_proxyauthorizeip.operation = 1 and mod_proxymngrtable.instance_id = $instance";
do_log "sql is $sql_add.";
if ($dbh->do($sql_add) != 0){
        do_log "There are access to add.";

        my $sth2 = $dbh->prepare($sql_add);
        $sth2->execute;

        while (my @row = $sth2->fetchrow_array) {
		my $sql_added = "UPDATE mod_proxyauthorizeip SET operation=0 WHERE id=$row[0]";

                if ($row[3] eq "0.0.0.0"){
			system("iptables -A INPUT -p tcp -s $row[1] --dport $row[4] -j ACCEPT\n");
		}else{
			system("iptables -A INPUT -p tcp -s $row[1] -d $row[3] --dport $row[4] -j ACCEPT\n");
		}
        	do_log "Updating: sql : $sql_added.";
		$dbh->do($sql_added);

		#my $time_add = localtime();
		#my $sql_log_add = "INSERT INTO proxymng_status (id, client_ip, backend_ip, backend_port, date, enabled) VALUES($row[5], '$row[1]', '$row[3]', '$row[4]', '$time_add', 1)";
        	#do_log "Updating: sql_log_add : $sql_log_add.";
		#$dbh->do($sql_log_add);
        }
}else{
        do_log "There are no access to add.";
}

