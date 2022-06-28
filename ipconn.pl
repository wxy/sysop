#!/usr/bin/perl

my $netstat = '/bin/netstat';
my $grep = '/bin/grep';
my $iptables = '/sbin/iptables';
my $killed_file = '/tmp/killedips';

my $level = 10;
my $port = 443;
my $class = 32;

my $killed = get_killed();
my $myip = get_me();
my $larges = get_data();

while (my $key = <>) {
    if ($key =~ /^[q|Q]$/) {
        print "Quit\n";
        exit;
    } elsif ($key eq '') {
    } elsif ($key =~ /^\d+$/) {
        if ($key <= scalar @{$larges}) {
            kill_ip($larges->[$key - 1]);
        }
    } elsif ($key =~ /^L(\d+)$/i) {
        $level = $1;
    } elsif ($key =~ /^P(\d+)$/i) {
        $port = $1;
    } elsif ($key =~ /^([c-d]{1})$/i) {
        $class = ($1 =~ /c/i)?24:32;
        $myip = get_me($class);
    }
    $larges = get_data();
}

sub get_data() {
    my $tmp_file = '/tmp/ipconn_'.$$.time();

    system("$netstat -an |$grep :$port > $tmp_file");

    open(TMP,"$tmp_file");

    # storge connection information
    my $conn = {};
    foreach my $line(<TMP>) {
        my ($proto,$recv_q,$send_q,$local,$foreign,$state) = split(/\s+/,$line);
        my ($foreign_address,$foreign_port) = split(/\:/,$foreign);
        if ($class == 24) {
            $ip = $foreign_address;
            $foreign_address = substr($foreign_address,0,rindex($foreign_address,'.') + 1) . '0';
        }
        $conn->{$foreign_address}{'ALL'}++;
        $conn->{$foreign_address}{$state}++;
        $conn->{$foreign_address}{'ip'}{$ip} += 1;
    }
    close(TMP);
    unlink($tmp_file);

    # count of large connection
    my $Large_Count = {};
    # count of all connection
    my $All_Count = {};

    # ips of large
    my @larges = ();
    our $id = 0;
    print "  Show Current Foreign IP Conntion to */$class:$port (>= $level)\n";
    print "   ID    Foreign Ip            All       SYN       EST       TIM       FIN  \n";
    print "┌──┬─────────┬─────┬────┬────┬────┬────┐\n";
    foreach our $foreign_address (sort {$conn->{$b}{'ALL'} <=> $conn->{$a}{'ALL'}} keys %{$conn}) {
        # all
        $All_Count->{'all'} += $conn->{$foreign_address}{'ALL'};
        $All_Count->{'syn'} += $conn->{$foreign_address}{'SYN_RECV'};
        $All_Count->{'est'} += $conn->{$foreign_address}{'ESTABLISHED'};
        $All_Count->{'tim'} += $conn->{$foreign_address}{'TIME_WAIT'};
        $All_Count->{'fin'} += $conn->{$foreign_address}{'FIN_WAIT1'};
        # large
        if ($conn->{$foreign_address}{'ALL'} >= $level) {
            our $id++;
            our $tag = ($killed->{$foreign_address})?"\033[0;31;1m*":(($foreign_address eq $myip)?"\033[0;32;1m#":' ');
            our $all = $conn->{$foreign_address}{'ALL'};$Large_Count->{'all'} += $all;
            $all .= '/' . (keys %{$conn->{$foreign_address}{'ip'}}) if ($class == 24);
            our $syn = $conn->{$foreign_address}{'SYN_RECV'};$Large_Count->{'syn'} += $syn;
            our $est = $conn->{$foreign_address}{'ESTABLISHED'};$Large_Count->{'est'} += $est;
            our $tim = $conn->{$foreign_address}{'TIME_WAIT'};$Large_Count->{'tim'} += $tim;
            our $fin = $conn->{$foreign_address}{'FIN_WAIT1'};$Large_Count->{'fin'} += $fin;
            push(@larges,$foreign_address);
            #format ip address
            $foreign_address = sprintf((($class == 24)?"\033[0;34;1m":'') . "%03d.%03d.%03d.%03d\033[0;31;0m",split(/\./,$foreign_address));
            printf ("│%3d │%1s%15s  │ %6s   │ %4d   │ %4d   │ %4d   │ %4d   │\n",
                $id,$tag,$foreign_address,$all ,$syn,$est,$tim,$fin);
            print "├──┼─────────┼─────┼────┼────┼────┼────┤\n";
        }
    }
    printf ("│    │ Above/All Count: │%4d/%4d │%3d/%3d │%3d/%3d │%3d/%3d │%3d/%3d │\n",
    $Large_Count->{'all'},$All_Count->{'all'},
    $Large_Count->{'syn'},$All_Count->{'syn'},
    $Large_Count->{'est'},$All_Count->{'est'},
    $Large_Count->{'tim'},$All_Count->{'tim'},
    $Large_Count->{'fin'},$All_Count->{'fin'});
    print "└──┴─────────┴─────┴────┴────┴────┴────┘\n";
    print "\nPlease input rule number that is inserted,or press 'q' for quit,or press 'r' for refresh: \n";
    print "Your choice : ";
    return \@larges;

}
sub kill_ip() {
    my $ip = shift;
    if (! $ip || $ip eq '0.0.0.0' || $ip eq $myip) {
        print "Error ip : $ip\n";
        return;
    }
    print "Kill : $ip\n";
    #system("iptables -I INPUT 1 -i eth0 -s $ip/$class -j DROP");
    #system("iptables -I OUTPUT 1 -o eth0 -d $ip/$class -j DROP");
    system("firewall-cmd --zone=drop --add-source=$ip/$class");
    open(KILLED,">>$killed_file");
    print KILLED "$ip/$class\t" . time() . "\n";
    close(KILLED);
    $killed->{$ip} = time();
}
sub get_killed() {
    # get killed ip
    open(KILLED,"$killed_file");
    my $killed = {};
    foreach $line(<KILLED>) {
        chop($line);
        my ($ip,$time) = split(/\s+/,$line);
        my ($ip) = split(/\//,$ip);
        $killed->{$ip} = $time;
    }
    close(KILLED);
    return $killed;
}
sub get_me() {
    my $class = shift || '32';
    my $tmp_file = '/tmp/ipconn_'.$$.time();

    system("$netstat -an |$grep :4022 > $tmp_file");

    open(TMP,"$tmp_file");

    # storge connection information
    my $me = '';
    foreach my $line(<TMP>) {
        my ($proto,$recv_q,$send_q,$local,$foreign,$state) = split(/\s+/,$line);
        my ($foreign_address,$foreign_port) = split(/\:/,$foreign);
        if ($state eq 'ESTABLISHED') {
            $me = $foreign_address;
            last;
        }
    }
    if ($class == 24) {
        $me = substr($me,0,rindex($me,'.') + 1) . '0';
    }
    close(TMP);
    unlink($tmp_file);
    return $me;
}
