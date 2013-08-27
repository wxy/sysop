#!/usr/bin/perl


my $netstat = '/bin/netstat';
my $grep = '/bin/grep';
my $iptables = '/sbin/iptables';
my $killed_file = '/tmp/killedips';

my $tmp_file = '/tmp/ipconn_'.$$.time();

system("$netstat -an |$grep :80 > $tmp_file");

open(TMP,"$tmp_file");

# storge connection information
my $conn = {};
foreach my $line(<TMP>)
    {
    my ($proto,$recv_q,$send_q,$local,$foreign,$state) = split(/\s+/,$line);
    my ($foreign_address,$foreign_port) = split(/\:/,$foreign);
    $conn->{$foreign_address}{'ALL'}++;
    $conn->{$foreign_address}{$state}++;
    }
close(TMP);
unlink($tmp_file);

# get killed ip
open(KILLED,"$killed_file");
my $killed = {};
foreach $line(<KILLED>)
    {
    chop($line);
    $killed->{$line} = 1;
    }
close(KILLED);

# count of large connection 
my $Large_Count = {};
# count of all connection
my $All_Count = {};

# ips of large
my @larges = ();
our $id = 0;
foreach our $foreign_address (sort {$conn->{$b}{'ALL'} <=> $conn->{$a}{'ALL'}} keys %{$conn})
    {
    # all
    $All_Count->{'all'} += $conn->{$foreign_address}{'ALL'};
    $All_Count->{'syn'} += $conn->{$foreign_address}{'SYN_RECV'};
    $All_Count->{'est'} += $conn->{$foreign_address}{'ESTABLISHED'};
    $All_Count->{'tim'} += $conn->{$foreign_address}{'TIME_WAIT'};
    $All_Count->{'fin'} += $conn->{$foreign_address}{'FIN_WAIT1'};
    # large
    if ($conn->{$foreign_address}{'ALL'} > 9)
        {
        our $id++;
        our $tag = ($killed->{$foreign_address})?'*':' ';
        our $all = $conn->{$foreign_address}{'ALL'};$Large_Count->{'all'} += $all;
        our $syn = $conn->{$foreign_address}{'SYN_RECV'};$Large_Count->{'syn'} += $syn;
        our $est = $conn->{$foreign_address}{'ESTABLISHED'};$Large_Count->{'est'} += $est;
        our $tim = $conn->{$foreign_address}{'TIME_WAIT'};$Large_Count->{'tim'} += $tim;
        our $fin = $conn->{$foreign_address}{'FIN_WAIT1'};$Large_Count->{'fin'} += $fin;
        push(@larges,$foreign_address);
        #format ip address
        $foreign_address = sprintf("%03d.%03d.%03d.%03d",split(/\./,$foreign_address));
        write STDOUT;
        }
    }
my $count = sprintf ("│    │ Above/All Count: │%4d/%4d │%3d/%3d │%3d/%3d │%3d/%3d │%3d/%3d │\n",
$Large_Count->{'all'},$All_Count->{'all'},
$Large_Count->{'syn'},$All_Count->{'syn'},
$Large_Count->{'est'},$All_Count->{'est'},
$Large_Count->{'tim'},$All_Count->{'tim'},
$Large_Count->{'fin'},$All_Count->{'fin'});
print $count;
print "└──┴─────────┴─────┴────┴────┴────┴────┘\n";

print "\nPlease input rule number that is inserted,or press 'q' for quit,or press 'r' for refresh: \n";
print "Your choice : ";
while  (my $key = <>) 
    {
    if ($key =~ /^[q|Q]$/)
        {
        print "Quit\n";
        exit;
        }
    elsif ($key =~ /^[r|R]$/)
        {
        print "Refresh\n";
        exec($0);
        }
    elsif ($key =~ /^[w|W]$/)
        {
        system("uptime");
        }
    elsif ($key =~ /^\d+(\D?)$/)
        {
        $second_key = $1;
        if ($key <= scalar @larges)
            {
            print "Deny : ".$larges[$key - 1]."\n";
            system("iptables -I INPUT 1 -i eth0 -s ".$larges[$key - 1]." -j DROP");            
            system("iptables -I OUTPUT 1 -o eth0 -d ".$larges[$key - 1]." -j DROP");
            open(KILLED,">>$killed_file");
            print KILLED $larges[$key - 1]."\n";
            close(KILLED);
            if ($second_key ne '')
                {
                if ($second_key =~ /^[q|Q]$/)
                    {
                    print "Quit\n";
                    exit;
                    }
                elsif ($second_key =~ /^[r|R]$/)
                    {
                    print "Refresh\n";
                    exec($0);
                    }
                elsif ($key =~ /^[w|W]$/)
                    {
                    system("uptime");
                    }
                }
            }
        }
    print "Your choice : ";
    }   
format STDOUT_TOP = 

  Show Current Foreign IP Conntion to *:80

   ID    Foreign Ip            All       SYN       EST       TIM       FIN  
┌──┬─────────┬─────┬────┬────┬────┬────┐
.
format STDOUT = 
│@>> │@<@<<<<<<<<<<<<<<<│   @>>>   │  @>>>  │  @>>>  │  @>>>  │  @>>>  │
$id $tag $foreign_address $all $syn $est $tim $fin
├──┼─────────┼─────┼────┼────┼────┼────┤
.
