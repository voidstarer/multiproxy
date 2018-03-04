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

read_db_connect_param();

sub do_log {
	my $message      = shift;
	my $time = localtime();
	return print "$time: main.pl: $message\n";
}

my $dbh = DBI->connect($db,$user,$pass) or die "[".localtime()."] Connection Error: $DBI::errstr\n";

my $sql_kill = "SELECT id, ip, port, thread_no, mod_proxymngrtable.restrict FROM mod_proxymngrtable WHERE status=2 and instance_id=$instance;";
if ($dbh->do($sql_kill) != 0){
        do_log "There are ports to remove.";

        my $sth = $dbh->prepare($sql_kill);
        $sth->execute;

        while (my @row = $sth->fetchrow_array) {
		my $sql_removed = "UPDATE mod_proxymngrtable SET status=3 WHERE id=$row[0]";
                if ($row[1] eq "0.0.0.0"){
			system("multiproxy-kill ".$row[2]);
        		do_log "Port $row[2] removed.";
			system("iptables -D INPUT -p tcp --dport $row[2] -m connlimit --connlimit-above $row[3] -j REJECT --reject-with tcp-reset\n");
			#system("iptables -D INPUT -p tcp --dport $row[2] -j ACCEPT\n");
		}else{
			system("multiproxy-kill ".$row[2]." ".$row[1]);
        		do_log "Port $row[2] removed on ip $row[1].";
			system("iptables -D INPUT -p tcp -d $row[1] --dport $row[2] -m connlimit --connlimit-above $row[3] -j REJECT --reject-with tcp-reset\n");
			#system("iptables -D INPUT -p tcp -d $row[1] --dport $row[2] -j ACCEPT\n");
		}
		$dbh->do($sql_removed);
		
		#REMOVING RESTRICTTIONS
		my @blocked_pages = split(',', $row[4]);
		
		foreach my $page (@blocked_pages) {
			do_log "Site $page blocked for port $row[2].";
			if ($row[1] ne "0.0.0.0"){
				system("iptables -D INPUT -p tcp -d $row[1] --dport $row[2] -m string --string '$page' --algo bm --from 1 --to 600 -j REJECT\n");
			}
			else{
				system("iptables -D INPUT -p tcp --dport $row[2] -m string --string '$page' --algo bm --from 1 --to 600 -j REJECT\n");
			}
		}
		
        }
}else{
        do_log "There are no ports to remove.";
}

my $sql_add = "SELECT id, pool, ip, port, time, thread_no, mod_proxymngrtable.restrict FROM mod_proxymngrtable WHERE status=1 and instance_id=$instance";
if ($dbh->do($sql_add) != 0){
        do_log "There are ports to add.";

        my $sth2 = $dbh->prepare($sql_add);
        $sth2->execute;

        while (my @row = $sth2->fetchrow_array) {
		my $sql_add_fix = "select mod_proxymngport.ip, mod_proxymngport.ports from mod_proxymngport, mod_proxymngproxyport where mod_proxymngport.id = mod_proxymngproxyport.proxylist and mod_proxymngproxyport.pool_id = $row[1]";
		do_log "sql_add_fix = $sql_add_fix";

		if ($dbh->do($sql_add_fix) != 0){
			my $sql_added = "UPDATE mod_proxymngrtable SET status=0 WHERE id=$row[0]";
		
			my $command = "multiproxy ";
			if ($row[1] != 0){
				$command = $command."-c ".$row[1]." ";
			}
			if ($row[2] ne "0.0.0.0"){
				$command = $command."-i ".$row[2]." ";
			}
			if ($row[3] != 0){
				$command = $command."-p ".$row[3]." ";
			}
			if ($row[4] != 0){
				$command = $command."-t ".$row[4]." ";
			}

			$command = $command."&";
			system($command);
			do_log "Rotator added on port $row[3] and ip $row[2].";
			$dbh->do($sql_added);
			if ($row[2] ne "0.0.0.0"){
				system("iptables -I INPUT -p tcp -d $row[2] --dport $row[3] -m connlimit --connlimit-above $row[5] -j REJECT --reject-with tcp-reset\n");
			}
			else{
				system("iptables -I INPUT -p tcp --dport $row[3] -m connlimit --connlimit-above $row[5] -j REJECT --reject-with tcp-reset\n");
			}
			do_log "Max connections limited to $row[5].";
		
			#APPLYING RESTRICTTIONS
			my @blocked_pages = split(',', $row[6]);
		
			foreach my $page (@blocked_pages) {
				do_log "Site $page blocked for port $row[3].";
				if ($row[2] ne "0.0.0.0"){
					system("iptables -I INPUT -p tcp -d $row[2] --dport $row[3] -m string --string '$page' --algo bm --from 1 --to 600 -j REJECT\n");
				}
				else{
					system("iptables -I INPUT -p tcp --dport $row[3] -m string --string '$page' --algo bm --from 1 --to 600 -j REJECT\n");
				}
			}
		
			#DEFAULT RULE
			if ($row[2] ne "0.0.0.0"){
				#system("iptables -A INPUT -p tcp -d $row[2] --dport $row[3] -j ACCEPT\n");
			}
			else{
				#system("iptables -A INPUT -p tcp --dport $row[3] -j ACCEPT\n");
			}
			#do_log "Accept rule created on port $row[3].";
	
		}
		else{
			my $sql_not_added = "UPDATE mod_proxymngrtable SET status=3 WHERE id=$row[0]";
			do_log "Rotator not added on port $row[3] and ip $row[2]. There are no proxies available on the pool";
	#		$dbh->do($sql_not_added);
		}

		
        }

}else{
        do_log "There are no ports to add.";
}

