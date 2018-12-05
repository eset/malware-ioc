# This script is a modified and tidied version of the signatures used by the
# Windigo operators to detect OpenSSH backdoors. It has been stripped to keep
# only the relevent parts.
#
# It is not guaranteed to run correctly. It is only to exhibit the full set of
# signatures.

my %pw = (
    '/usr/include/gpm2.h'                => 0,
    '/lib/initr'                         => 0,
    '/usr/include/symc.h'                => 0,
    '/usr/include/pwd2.h'                => 0,
    '/var/lib/nfs/gpm2.h'                => 0,
    '/usr/share/sshd.sync'               => 0,
    '/rescue/mount_fs'                   => 0,
    '/usr/lib/libiconv.so.0'             => 0,
    '/usr/share/man/mann/options'        => 0,
    '/etc/ssh/.sshd_auth'                => 0,
    '/usr/lib/.sshd.h'                   => 0,
    '/usr/include/kix.h'                 => 0,
    '/usr/include/pthread2x.h'           => 0,
    '/tmp/.lost+found'                   => 0,
    '/usr/lib/jlib.h'                    => 0,
    '/usr/include/zaux.h'                => 0,
    '/usr/local/include/uconf.h'         => 0,
    '/usr/include/netda.h'               => 0,
    '/usr/include/salt.h'                => 0,
    '/usr/include/zconf2.h'              => 0,
    '/usr/lib/libm.c'                    => 0,
    '/etc/gpufd'                         => 0,
    '/usr/include/syslog2.h'             => 0,
    '/var/run/.options'                  => 0,
    '/usr/include/lwpin.h'               => 0,
    '/usr/lib/libsplug.2.so'             => 0,
    '/dev/devno'                         => 0,
    '/usr/include/ncurse.h'              => 0,
    '/usr/include/linux/byteorder/ssh.h' => 0,
    '/usr/include/client.h'              => 0,
    '/usr/include/linux/byteorder/ssh.h' => 0,
    '/var/log//.login'                   => 0,
    '/usr/ofed/bin/bin'                  => 0,
    '/usr/ofed/bin/ssh'                  => 0,
    '/usr/lib/libsplug.4.so'             => 0,
    '/usr/share/core.h'                  => 0,
    '/usr/games/.blane'                  => 0,
    '/tmp/.ICE-unix/error.log'           => 0,
    '/usr/lib/.sshd.h'                   => 0,
    '/usr/include/filearch.h'            => 0,
    '/usr/include/usr.h'                 => 0,
    '/var/html/lol'                      => 0,
    '/etc/listpr'                        => 0,
    '/usr/share/boot.sync'               => 0,
    '/usr/include/true.h'                => 0,
    '/var/run/npss.state'                => 0,
    '/var/run/.ssh.pid'                  => 0,
    '/usr/lib/libQtNetwork.so.4.0.1'     => 0,
    '/bin/.ilog'                         => 0,
    '/bin/.olog'                         => 0,
    '/usr/include/.o'                    => 0,
    '/usr/include/.i'                    => 0,
    '/tmp/zilog'                         => 0,
    '/tmp/zolog'                         => 0,
    '/usr/include/sn.h'                  => 0,
    '/usr/include/ide.h'                 => 0,
    '/usr/lib/libgssapi_krb5.so.9.9'     => 0,
    '/etc/security/pam_env'              => 0,
    '/usr/lib/rpm/rpm.cx'                => 0,
    '/dev/saux'                          => 0,
    '/tmp/sess.rotat'                    => 0,

    # binary
    '/usr/include/boot.h'                => 0,
    '/usr/include/linux/arp.h'           => 0,
    '/usr/include/libssh.h'              => 0,
    '/usr/include/linux/boot.h'          => 0,
    '/usr/games/.lost+found'             => 0,
    '/var/run/proc.pid'                  => 0,
    '/var/run/lvm//lvm.pid'              => 0,
    '/usr/include/linux/netfilter/ssh.h' => 0,
    '/usr/lib/libtools.x'                => 0,
    '/usr/include/mbstring.h'            => 0,
    '/usr/include/linux/sys/sysp2.h'     => 0,
    '/tmp/.rewt'                         => 0,
    '/var/run/+++screen.run'             => 0,
    '/var/run/+++php.run'                => 0,
    '/tmp/.datass'                       => 0,
    '/dev/...'                           => 0,

    # non-passwd, files from sshd_str
    '/usr/libexec/ssh-keysign' => 1,
    '/bin/passwd'              => 1,
    '/dev/zero'                => 1,
    '/dev/null'                => 1,
    '/dev/urandom'             => 1,
    '/dev/random'              => 1,
    '/usr/bin/curl'            => 1,
    '/usr/local/bin/curl'      => 1

      # usermode rootkit '/usr/include/file.h' => 0, '/etc/sh.conf' => 0
);

my $bsshd;
my $bssh;
my @bsshd;
my @bssh;

sub dump_passwd {
    my $f = shift;
    return unless $f;
    return if $pw{$f};
    $pw{$f}++;
    return unless -f $f;
    print "mod_str_ : ";
    system("ls -l '$f'");
    my ( $fn, $fc );
    open( $fn, "<$f" );
    read( $fn, $fc, 32 );
    close $fn;

    if ( $fc !~ /[\x00-\x07\x0B-\x1F\x7F-\xFF]/ ) {
        system("tail -n 5000 '$f'");
    }
    else {
        $fc =~ s|(.)|~$1|esg;
        if ( $fc =~ /[\x00-\x07\x0B-\x1F\x7F-\xFF]/ ) {
            print "$f : crypted, skip\n";
            return;
        }
        open( $fn, "<$f" );
        seek( $fn, -100 * 1024, 2 );
        read( $fn, $fc, 150 * 1024 );
        close $fn;
        $fc =~ s|(.)|~$1|esg;
        print $fc. "\n";
    }
}

sub ssh_ls {
    for (@_) { dump_passwd($_) }
    return if $sshls;
    system('ls -al /usr/bin/ssh* /usr/sbin/ssh* ');
    $sshls++;
}

sub pgrep {
    my $a = shift;
    my $s = shift;
    my $p = shift;
    my @out;
    my @idx;
    for ( 0 .. ( scalar @{$a} ) - 1 ) { push @idx, $_ if ($a)->[$_] =~ /$s/ }
    return unless @idx;
    my $min;
    my $max;
    my @p = split( /\s+/, $p ) if $p;

    while (@p) {
        my $t = shift @p;
        if    ( $t eq '-B' ) { $min = shift @p }
        elsif ( $t eq '-A' ) { $max = shift @p }
        elsif ( $t eq '-C' ) { $min = shift @p; $max = $min }
        else { warn "perl_strings: wrong param: '$t@p'\n"; last }
    }
    my $idx = shift @idx;
    if (@idx) { warn "'$s' - multipattern !!!\n" }
    if   ( defined $min ) { $min = $idx - $min }
    else                  { $min = $idx }
    if   ( defined $max ) { $max = $idx + $max }
    else                  { $max = $idx }

    #printf "'%s','%s': %d: %s\n",$s,$p,$idx,join(",",$min..$max);
    for ( $min .. $max ) { push @out, ($a)->[$_] }
    return @out;
}

sub gs { my $s = shift; my $p = shift; return pgrep( \@bsshd, $s, $p ) }
sub gc { my $s = shift; my $p = shift; return pgrep( \@bssh,  $s, $p ) }

sub load_bin {
    local $/ = undef;
    @bsshd = ();
    @bssh  = ();
    $bsshd = '';
    $bssh  = '';
    my $f;
    if ( open( $f, "</usr/sbin/sshd" ) ) {
        $bsshd = <$f>;
        close $f;
        @bsshd = ( $bsshd =~ /([\x09\x20-\x7e]{4,})/g );
    }
    else { warn "perl_strings: can't open sshd\n" }
    if ( open( $f, "</usr/bin/ssh" ) ) {
        $bssh = <$f>;
        close $f;
        @bssh = ( $bssh =~ /([\x09\x20-\x7e]{4,})/g );
    }
    else { warn "perl_strings: can't open ssh\n" }
}

sub check_binary {
    my @sd;
    my @sc;
    load_bin();
    if ( $dssh =~ m|, SSH protocols 1.5/2.0, | ) {
        print "mod_ssh: \n";
        @sd = gs( '%s : %s', '-B 2' );
        @sc = gc( '%s : %s', '-B 2' );
        if ( f $sd[1] or f $sc[1] ) {
            print
              "mod_sshd01: '$sd[0]':'$sd[1]'\nmod_sshc01: '$sc[0]':'$sc[1]'\n";
            ssh_ls( $sd[1], $sc[1] );
        }
        @sd = gs( '%s:%s', '-B 2' );
        @sc = gc( '%s:%s', '-B 2' );
        if ( f $sd[1] or f $sc[1] ) {
            print
              "mod_sshd02: '$sd[0]':'$sd[1]'\nmod_sshc02: '$sc[0]':'$sc[1]'\n";
            ssh_ls( $sd[1], $sc[1] );
        }
    }

    @sd = gs( 'SSH-1.5-W1.0', '-A 15' );
    @sc = gc( 'mkdir -p %s', '-A 2' );
    if ( @sc or f $sd[2] ) {
        print "mod_sshd1: '$sd[1]':'$sd[2]'\n";
        print "mod_sshc1: '$sc[1]':'$sc[2]'\n";
        ssh_ls( $sd[2] );
    }
    if ( f $sd[4] ) {
        print "mod_sshd1a: file:'$sd[4]'; hash:'$sd[15]'; cvs:'$sd[1]'\n";
        ssh_ls( $sd[4] );
    }
    @sd = gs( '\.rhosts', '-A 3' );
    if ( f $sd[1] ) {
        print "mod_sshd2: '$sd[1]':'$sd[2]':'$sd[3]'\n";
        ssh_ls( $sd[1] );
    }
    @sd = gs('/usr/share/man/mann/options');
    @sc = gc('/usr/share/man/mann/options');
    if (@sd) {
        my $k;
        my @s;
        @s = gs( 'apac', '-A 3' );
        $k = 1
          if ( $s[0] =~ /^apache!s/ and $s[1] =~ /^status-o/ )
          or ( $s[0] eq 'apac' and $s[2] eq 'stat' );
        @s = gs( 'GftR', '-A 3' );
        $k = 2
          if ( $s[0] =~ /^GftRudW!/ and $s[1] =~ /^pezdecov/ )
          or ( $s[0] eq 'GftR' and $s[2] eq 'pezd' );
        @s = gs( 'dont', '-A 3' );
        $k = 3
          if ( $s[0] =~ /^dontxekm/ and $s[1] =~ /^superhos/ )
          or ( $s[0] eq 'dont' and $s[2] eq 'supe' );
        @s = gs( 'IAd5', '-A 3' );
        $k = 4 if ( $s[1] =~ 'repo' or $s[2] =~ 'repo' );
        @s = gs( '3Oje', '-A 3' );
        $k = 5 if map /^repo/, @s;
        printf "mod_sshd03: $sd[0]; known: %d\n", $k;
        ssh_ls( $sd[0] );
    }
    if (@sc) {
        my $k;
        my @s;
        @s = gc( 'apac', '-A 3' );
        $k = 1
          if ( $s[0] =~ /^apache!s/ and $s[1] =~ /^status-o/ )
          or ( $s[0] eq 'apac' and $s[2] eq 'stat' );
        @s = gc( 'GftR', '-A 3' );
        $k = 2
          if ( $s[0] =~ /^GftRudW!/ and $s[1] =~ /^pezdecov/ )
          or ( $s[0] eq 'GftR' and $s[2] eq 'pezd' );
        @s = gc( 'dont', '-A 3' );
        $k = 3
          if ( $s[0] =~ /^dontxekm/ and $s[1] =~ /^superhos/ )
          or ( $s[0] eq 'dont' and $s[2] eq 'supe' );
        @s = gc( 'IAd5', '-A 3' );
        $k = 4 if ( $s[1] =~ 'repo' or $s[2] =~ 'repo' );
        @s = gc( '3Oje', '-A 3' );
        $k = 5 if map /^repo/, @s;
        printf "mod_sshc03: $sc[0]; known: %d\n", $k;
        ssh_ls( $sc[0] );
    }
    @sd = gs( 'Sshd password detected', '-B 2' );
    @sc = gc( 'User %s connecting as %s', '-A 1' );
    print "mod_sshc4: '$sc[1]':'$sc[0]'\n" if @sc and f $sc[1];
    if ( $sd[1] && f $sd[1] ) {
        print "mod_sshd4: '$sd[0]':'$sd[1]':'$sd[2]'\n";
        ssh_ls( $sd[1] );
    }
    @sd = gs( 'trying public RSA key file %s', '-B 6' );
    if ( f $sd[0] ) {
        print "mod_sshd5: " . join( '|', @sd ) . "\n";
        ssh_ls( $sd[0] );
    }
    @sd = gs( ' %s:%s', '-C 1' );
    @sc = gc( ' %s:%s', '-C 1' );
    if ( f $sd[0] ) {
        print "mod_sshd6: '$sd[2]':'$sd[0]'\nmod_sshc6: '$sc[0]'\n";
        ssh_ls( $sd[0] );
    }
    @sd = gs( 'SSH-1.5-W1.0', '-B 5' );
    @sc = gc( 'mkdir -p %s', '-B 1' );
    if ( f $sd[4] ) {
        print "mod_sshd7: '$sd[0]':'$sd[4]'\nmod_sshc7: '$sc[0]'\n";
        ssh_ls( $sd[4] );
    }
    @sd = gs( 'user: %s', '-A 2' );
    @sc = gc( 'user: %s', '-A 1' );
    if ( f $sd[2] ) {
        print "mod_sshd8: '$sd[1]':'$sd[2]'\nmod_sshc8: '$sc[1]'\n";
        ssh_ls( $sd[1] );
    }
    @sd = gs( 'user: %s', '-B 2' );
    @sc = gc( 'user: %s', '-A 20' );
    if ( f $sd[1] ) {
        print
"mod_sshd9: '$sd[0]':'$sd[1]':'$sd[2]'\nmod_sshc9: '$sc[20]':'$sc[19]':'$sc[0]'\n";
        ssh_ls( $sd[1], $sc[20] );
    }
    @sd = gs( '%Y-%m-%d %H:%M:%S', '-B 2 -A 9' );
    @sc = gc( '%Y-%m-%d %H:%M:%S', '-B 2 -A 10' );
    if ( f $sd[11] ) {
        print
"mod_sshd10: '$sd[0]':'$sd[1]':'$sd[11]'\nmod_sshc10: '$sc[0]':'$sc[1]':'$sc[12]'\n";
        ssh_ls( $sd[11], $sc[12] );
    }
    @sd = gs( 'incoming : %s:%s', '-B 2' );
    @sc = gc( 'mkdir -p %s', '-A 1' );
    if ( f $sd[1] ) {
        print
"mod_sshd11: '$sd[0]':'$sd[1]':'$sd[2]'\nmod_sshc11: '$sc[0]':'$sc[1]'\n";
        ssh_ls( $sd[1], $sc[1] );
    }
    @sd = gs('pwd:+%.64s+%.64s+%.64s');
    if (@sd) { print "mod_sshd12: GET, no params"; ssh_ls() }
    @sd = gs( '%s:%s', '-B 3' );
    @sc = gc( '%s:%s@%s', '-B 2' );
    if ( f $sd[1] and f $sd[2] ) {
        print
"mod_sshd13: hash:'$sd[0]':'$sd[1]':'$sd[2]'\nmod_sshc13: hash:'$sc[0]':'$sc[1]'\n";
        ssh_ls( $sd[2] );
    }
    @sd = gs( '%Y-%m-%d %H:%M:%S', '-A 4' );
    @sc = gc( '%Y-%m-%d %H:%M:%S', '-A 4' );
    if ( f $sd[2] ) {
        print "mod_sshd14: hash:'$sd[3]':'$sd[4]':'$sd[2]'\n";
        print "mod_sshc14: hash:'$sd[3]':'$sd[4]':'$sd[2]'\n";
        ssh_ls( $sd[2] );
    }
    @sd = gs( '%Y-%m-%d %H:%M:%S', '-A 14' );
    @sc = gc( '%Y-%m-%d %H:%M:%S', '-A 12' );
    if ( f $sd[3] ) {
        my $hp;
        for ( 5 .. 15 ) {
            if ( $sd[$_] =~ /^\$1\$/ and ( length $sd[$_] == 30 ) ) {
                $hp = $sd[$_];
                last;
            }
        }
        if ($hp) {
            print
"mod_sshd14: hash:'$hp'; fpass:'$sd[1]';'$sd[3]'\nmod_sshc14: hash:'$sd[4]'; fpass:'$sd[1]';'$sd[3]'\n";
        }
        else { print "mod_sshd14: unknown hash; fpass:'$sd[1]';'$sd[3]'\n" }
        ssh_ls( $sd[3] );
        if ( $sd[1] ) {
            my $k = $sd[1];
            $k =~ s/(.|\n)/sprintf("%02lx", ord $1)/eg;
            my $f;
            if (
                open(
                    $f,
"openssl enc -d -des-ede3-cbc -in $sd[3] -K $k -iv '' 2>/dev/null |"
                )
              )
            {
                my $d;
                while ( sysread( $f, $d, 0x100, 0 ) ) {
                    $d =~ s/\0+//;
                    $d = substr( $d, 9 );
                    print "mod14p: $d\n";
                }
                close $f;
            }
        }
    }
    @sd = gs( 'Inbound: %s %s', '-C 1' );
    @sc = gc( 'Outbound: %s %s %s', '-B 39' );
    if ( f $sd[2] or f $sc[0] ) {
        print "mod_sshd15: '$sd[0]':'$sd[2]'\n";
        print "mod_sshc15: '$sc[38]':'$sc[0]'\n";
        ssh_ls( $sd[2] );
    }
    @sd = gs( 'sshd password detected: %s@%s:%s', '-B 2' );
    @sc = gc( 'User %s, connecting as %s@%s', '-A 1' );
    if ( f $sd[1] or f $sc[1] ) {
        print "mod_sshd16: '$sd[0]':'$sd[1]'\n";
        print "mod_sshc16: '$sc[1]':'$sc[0]'\n";
        ssh_ls( $sd[1] );
    }
    @sd = gs( 'mkdir -p %s', '-C 1' );
    @sc = gc( 'mkdir -p %s', '-B 1' );
    if ( f $sd[0] or f $sc[0] ) {
        print "mod_sshd17: crypt:'$sd[2]':'$sd[0]'\n";
        print "mod_sshc17: '$sc[0]':'$sc[1]'\n";
        my @q = gs( 'SSH-1.5-W1.0', '-A 1' );
        print "mod_sshd17: client_string:'$q[1]'\n";
        ssh_ls( $sd[0] );
    }
    @sd = gs( 'SSH AGENT', '-C 2' );
    @sc = gc( 'SSH AGENT', '-C 2' );
    if ( f $sd[0] or f $sc[1] ) {
        print "mod_sshd18: md5:'$sd[3]':'$sd[0]'\n";
        print "mod_sshc18: md5:'$sc[3]':'$sc[0]'\n";
        ssh_ls( $sd[0] );
    }
    @sd = gs( '/usr/bin/curl', '-C 3' );
    if ( f $sd[1] ) {
        print "mod_sshd19: '$sd[0]':'$sd[1]' url:'$sd[5] '$sd[4]'\n";
        ssh_ls( $sd[1] );
    }
    @sd = gs( 'login in: %s:%s', '-B 2' );
    @sc = gc( 'login at: %s %s:%s', '-B 2' );
    if ( f $sd[1] or f $sc[1] ) {
        print "mod_sshd20: '$sd[0]':'$sd[1]'\n";
        print "mod_sshc20: '$sc[0]':'$sc[1]'\n";
        ssh_ls( $sd[1], $sc[1] );
    }
    @sc = gc( 'outgoing : %s %s:%s', '-B 2' );
    @sd = gs( $sc[0] ) if f $sc[1];
    if ( f $sc[1] and @sd ) {
        print "mod_sshd21: '$sd[0]' mod_sshc21: '$sc[0]':'$sc[1]'\n";
        ssh_ls( $sc[1] );
    }
    @sd = gs( 'user:password --> %s:%s', '-B 2' );    #@sc=gc();
    if ( f $sd[1] ) {
        print "mod_sshc22: '$sd[0]':'$sd[1]':'$sd[2]'\n";
        ssh_ls( $sd[1] );
    }
    @sd = gs( 'From: %s - %s:%s', '-C 1' );
    @sc = gc( 'To: %s - %s:%s', '-B 2' );
    if ( f $sd[0] or f $sc[1] ) {
        print "mod_sshd23: '$sd[2]':'$sd[0]'\n";
        print "mod_sshc23: '$sc[0]':'$sc[1]'\n";
        ssh_ls( $sd[0], $sc[1] );
    }
    @sd = gs( 'rcpt to: ', '-B 21' );
    @sc = gc( 'ssh: av\[%d\]: %s', '-A 1' );
    if ( f $sd[17] or f $sc[1] ) {
        print "mod_sshd24: '$sd[0]':'$sd[17]':'$sd[18]:$sd[20]'\n";
        print "mod_sshc24: '$sc[1]':'$sc[0]'\n";
        ssh_ls( $sd[17], $sc[1] );
    }
    @sd = gs( '< %s %s', '-C 1' );
    @sc = gc( '> %s %s %s', '-B 1' );
    if ( f $sd[0] or f $sc[0] ) {
        print "mod_sshd25: '$sd[2]':'$sd[0]' mod_sshc25: '$sc[0]'\n";
        ssh_ls( $sd[0], $sc[0] );
    }
    @sd = gs( '%s:%s', '-C 1' );
    @sc = gc('GET /\?sid=');
    if ( $sd[2] =~ m|^GET | or @sc ) {
        my @sd1 = gs( 'f:p:b:k:h:g:u:o:dDeiqrtQR46', '-B 1' );
        my @sc1 = gc( 'clear hostkey %d', '-B 1' );
        print
"mod_sshd26: '$sd[0]':'$sd[2]':'$sd1[0]' mod_sshc26: '$sc[0]':'$sc1[0]'\n";
        ssh_ls();
    }
    @sd = gs( '%s:%s', '-B 3' );
    @sc = gc( '%s@%s:%s', '-B 1' );
    if ( ( f $sd[2] and $sd[1] =~ /^cat / ) or f $sc[0] ) {
        print "mod_sshd27: '$sd[0]':'$sd[2]':'$sd[1]'\nmod_sshc27: '$sc[0]'\n";
        ssh_ls( $sd[2], $sc[0] );
    }
    #
    @sd = gs('/var/log/httpd-access.log');
    @sc = gc('/var/log/httpd-access.log');
    if (@sd) {
        my @xbin1 = ( $bsshd =~ /([\x01-\x7e]{6,})/g );
        my @xbin2;
        foreach my $q (@xbin1) {
            my $xbin = $q ^ chr(0x23) x length $q;
            push @xbin2, ( $xbin =~ /([\x09\x20-\x7e]{6,})/g );
        }
        @sd = pgrep( \@xbin2, 'id=%s&m=%s', '-B 3' );
    }
    if (@sc) {
        my @xbin1 = ( $bssh =~ /([\x01-\x7e]{6,})/g );
        my @xbin2;
        foreach my $q (@xbin1) {
            my $xbin = $q ^ chr(0x23) x length $q;
            push @xbin2, ( $xbin =~ /([\x09\x20-\x7e]{6,})/g );
        }
        @sc = pgrep( \@xbin2, 'id=%s&m=%s', '-B 3' );
    }
    if ( @sd or @sc ) {
        print
"mod_sshd28: '$sd[2]':'$sd[1]':'$sd[0]':'$sd[3]'\nmod_sshc28: '$sc[2]':'$sc[1]':'$sc[0]':'$sc[3]'\n";
        ssh_ls( $sd[0], $sc[0] );
    }
    #
    @sd = gs( 'IN: %s@ \(%s\) ', '-B 2' );
    @sc = gc( 'OUT=> %s@%s \(%s\)', '-B 1' );
    if ( f $sd[1] or f $sc[0] ) {
        print
"mod_sshd29: '$sd[0]':'$sd[1]':'$sd[2]'\nmod_sshc29: '$sc[0]':'$sc[1]'\n";
        ssh_ls( $sd[1], $sc[0] );
    }
    @sd = gs( 'PPAM: h: %s, u: %s, p: %s', '-C 3' );
    @sc = gc( '%s%s, p: %s, key:', '-B 5' );
    @sc = gc( '%s%s %skey:', '-B 6' ) unless @sc;
    if ( f $sd[4] or f $sc[2] ) {
        print
"mod_sshd30: '$sd[3]';hash:'$sd[2]':'$sd[6]';$sd[4]':'$sd[5]'\nmod_sshc30: '$sc[5]';hash:'$sc[0]':???;'$sc[2]'\n";
        ssh_ls( $sd[4], $sd[5], $sc[2] );
    }

    @sd = gs('IN: %s -> %s : %s');
    if (@sd) {
        my @xbin1 = ( $bsshd =~ /([\x01-\x7e]{6,})/g );
        my @xbin2;
        foreach my $q (@xbin1) {
            $q = $q ^ chr(0x22) x length $q if $q =~ /[\x00-\x09\x0B-\x1F]/;
            push @xbin2, ( $q =~ /([\x20-\x7e]{6,})/g );
        }
        @sd = pgrep( \@xbin2, 'IN: %s -> %s : %s', '-A 2' );
    }

    if ( f $sd[1] ) {
        print "mod_sshd31: hash:'$sd[2]':'$sd[1]':'$sd[0]'\n";
        ssh_ls( $sd[1] );
    }    #2do decrypt $sd[1] xor \x22
    @sd = gs( '%Y-%m-%d %H:%M:%S', '-C 1' );
    @sc = gc( '%Y-%m-%d %H:%M:%S', '-C 1' );
    $sd[2] .= '';
    $sc[2] .= '';
    if (    ( $sd[2] eq '[%s] ' or $sc[2] eq '[%s] ' )
        and ( f $sd[0] or f $sc[0] ) )
    {
        my @sd1 = gs( '\[PASSWORD\] KRB5-AUTH success! %s:%d ', '-C 1' );
        print "mod_sshd32: md5:'$sd1[0]:'$sd[0]':'$sc[0]'\n";
        ssh_ls( $sd[0] );
    }

    @sd = gs( 'trying public RSA key file %s', '-B 2' );
    @sc = gc( '%s:%s@%s', '-B 1' );
    if ( f $sd[1] or f $sc[0] ) {
        print "mod_sshd33: '$sd[0]':'$sd[1]':'$sc[0]'\n";
        ssh_ls( $sd[1], $sc[0] );
    }

    sub h34_decr {
        my $c = shift;
        my $res;
        my $a =
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ. 0123456789:?'
          . 'abcdefghijklmnopqrstuvwxyz/'
          . "\xDA\xB9\xB2\xB3\xA3\xA2\xAC\xCF\xE3\xF8\xE0\xCE\xE4";
        my @c = split( //, $c );
        for (@c) {
            my $i = index( $a, $_ );
            if    ( $i == -1 ) { $i = 39 }
            elsif ( $i < 40 )  { $i = ( $i + 20 ) % 40 }
            else               { $i = ( $i + 20 ) % 40 + 40 }
            $res .= substr( $a, $i, 1 );
        }
        return $res;
    }

    @sd = gs( 'entrou: %s u: %s p: %s', '-C 4' );
    @sc = gc( 'saiu1: %s u: %s p: %s', '-A 4' );
    if ( @sd or @sc ) {
        my @xbin1 =
          ( $bsshd =~
/([\x20\x25\x2e-\x7a\xDA\xB9\xB2\xB3\xA3\xA2\xAC\xCF\xE3\xF8\xE0\xCE\xE4]{5,})/g
          );
        @sd = pgrep( \@xbin1, 'entrou: %s u: %s p: %s', '-C 3' );
        my @sdd;
        for ( @sd[ 4 .. 6 ] ) { push @sdd, h34_decr($_) }
        my @xbin2 =
          ( $bssh =~
/([\x20\x25\x2e-\x7a\xDA\xB9\xB2\xB3\xA3\xA2\xAC\xCF\xE3\xF8\xE0\xCE\xE4]{5,})/g
          );
        @sc = pgrep( \@xbin2, 'saiu1: %s u: %s p: %s', '-A 3' );
        my @scd;
        for ( @sc[ 1 .. 3 ] ) { push @scd, h34_decr($_) }
        print
"mod_sshd34: hash:'$sd[2]' '$sdd[0]':'$sdd[1]':'$sdd[2]'\nmod_sshc34: '$scd[0]':'$scd[1]':'$scd[2]'\n";
        ssh_ls( $sdd[0], $scd[0] );
    }

    sub h35_decr {
        my $f = shift;
        my $c = shift;
        $c = $c x 100;
        my $fn;
        open( $fn, "<$f" );
        seek( $fn, -400 * 1024, 2 );
        my $q = <$fn>;
        while ( $q = <$fn> ) {
            chomp $q;
            my @q = split( //, $q );
            for (@q) { $_ = chr( ord($_) - 12 ) }
            $q = join( '', @q );
            $q = $q ^ substr( $c, 0, length $q );
            print $q. "\n";
        }
        close $fn;
    }
    @sd = gs( 'trying public RSA key file %s', '-B 3' );
    @sc = gc( '%s:%s@%s', '-C 1' );
    if ( ( f $sd[1] and f $sd[2] ) or f $sc[2] ) {
        print
"mod_sshd35: '$sd[0]' pid:'$sd[1]':'$sd[2]' '$sc[0]':'$sc[1]':'$sc[2]'\n";
        ssh_ls( $sd[1], $sd[2], $sc[2] );
        for ( $sd[1], $sd[2], $sc[2] ) {
            h35_decr( $_, $sd[0] ? $sd[0] : $sc[0] ) if -f $_;
        }
    }
    @sd = gs( '/tmp/sess_', '-B 1' );
    @sc = gc( '/tmp/sess_', '-B 1' );
    $sd[0] .= '';
    $sc[0] .= '';
    if ( $sd[0] =~ m|^[\da-f]{32}$| or $sc[0] =~ m|^[\da-f]{32}$| ) {
        print "mod_sshd36: md5:'$sd[0]':'$sc[0]'; '$sd[1]':'$sc[1]'\n";
        ssh_ls();
    }
    @sd = gs( 'INCORRECT', '-C 2' );
    if ( f $sd[1] and f $sd[3] ) {
        print "mod_sshd37: md5:'$sd[0]'; '$sd[1]':'$sd[3]'\n";
        ssh_ls( $sd[1] );
    }

    @sd = gs('\|\|\|SSH AGENT\|\|\|');
    @sc = gc('\|\|\|SSH AGENT\|\|\|');
    if ( @sd or @sc ) { ssh_ls() }
    if (@sd) {
        my $kcr;
        my $kh1;
        my $kh2;
        $kcr = 1 if scalar gs('u\|f=GVvB');
        $kh1 = 1 if gs('Mjgg5yBS');
        $kh2 = 1 if scalar gs('MjUg5yBS');
        $kcr = 1 if scalar gs('u\|f=GVvB');
        $kh1 = 2 if gs('Mjkg5yBS');
        $kh2 = 2 if scalar gs('MjYg5yBS');
        $kcr = 1 if scalar gs('u\|f=GVvB');
        $kh1 = 3 if gs('ao\+v2b2L');
        $kh2 = 3 if scalar gs('ao\+v2b2L');
        $kcr = 1 if scalar gs('u\|f=GVvB');
        $kh1 = 4 if gs('NDAg\+SxD');
        $kh2 = 4 if scalar gs('NDAg\+SxD');
        printf "mod_sshd38: '%s'; kcrypt:%d, khost1:%d, khost2:%d\n", $sd[0],
          $kcr, $kh1, $kh2;
    }
    if (@sc) {
        my $kcr;
        my $kh1;
        my $kh2;
        $kcr = 1 if scalar gc('u\|f=GVvB');
        $kh1 = 1 if gc('Mjgg5yBS');
        $kh2 = 1 if scalar gc('MjUg5yBS');
        $kcr = 1 if scalar gc('u\|f=GVvB');
        $kh1 = 2 if gc('Mjkg5yBS');
        $kh2 = 2 if scalar gc('MjYg5yBS');
        $kcr = 1 if scalar gc('u\|f=GVvB');
        $kh1 = 3 if gc('ao\+v2b2L');
        $kh2 = 3 if scalar gc('ao\+v2b2L');
        $kcr = 1 if scalar gc('u\|f=GVvB');
        $kh1 = 4 if gc('NDAg\+SxD');
        $kh2 = 4 if scalar gc('NDAg\+SxD');
        printf "mod_sshc38: '%s'; kcrypt:%d, khost1:%d, khost2:%d\n", $sc[0],
          $kcr, $kh1, $kh2;
    }

    @sd = gs('getifaddrs');
    @sc = gc('getifaddrs');
    if (@sd) {
        my $k;
        $k = 1 if $bsshd =~ /\xDD\x38\xD7\x60\x94\x6E\xE0\x9A\x38\x5C/;
        $k = 2
          if $bsshd =~
          /\xD3\x38\xD3\x6D\x8F\x78\xA9\xC8\x2B\x4A\x6B\x57\xD5\x75/;
        $k = 3 if $bsshd =~ /\xDA\x71\x81\x35\x99\x6D\xA3\xDE\x7B\x00/;
        $k = 4 if $bsshd =~ /\xCE\x29\xD8\x67\x93\x66\xE9\xC0\x3C\x5D/;
        printf "mod_sshd39: detected, known:%d\n", $k;
        ssh_ls();
    }
    if (@sc) {
        my $k;
        $k = 1 if $bssh =~ /\xDD\x38\xD7\x60\x94\x6E\xE0\x9A\x38\x5C/;
        $k = 2
          if $bssh =~
          /\xD3\x38\xD3\x6D\x8F\x78\xA9\xC8\x2B\x4A\x6B\x57\xD5\x75/;
        $k = 3 if $bssh =~ /\xDA\x71\x81\x35\x99\x6D\xA3\xDE\x7B\x00/;
        $k = 4 if $bsshd =~ /\xCE\x29\xD8\x67\x93\x66\xE9\xC0\x3C\x5D/;
        printf "mod_sshc39: detected, known:%d\n", $k;
        ssh_ls();
    }

    @sd = gs( 'LOCAL: %s -> %s : %s ', '-C 1' );
    if (@sd) {
        my $sd2 = $sd[2] ^ "\x17" x length $sd[2];
        my $sd0 = $sd[0] ^ "\x17" x length $sd[0];
        printf "mod_sshd40: crypt:'%s':'%s':'%s'\n", $sd2, $sd0, $sd[1];
        ssh_ls($sd0);
        my $fn;
        open( $fn, "<$sd0" );
        seek( $fn, -100 * 1024, 2 );
        while (<$fn>) { chomp; print $_ ^ "\x14" x length $_ }
        close $fn;
    }

    sub h41_decr1 {
        my $q = shift;
        my @q = split( //, $q );
        my $z = 1;
        for ( 0 .. length $q ) {
            $q[$z] = ord( $q[$z] ) ^ $_;
            $q[$z] = $q[$z] ^ 0x31;
            $q[$z] = chr( $q[$z] & 0xff );
            $z     = $_ + 2;
        }
        return substr( join( '', @q ), 1, ord $q[0] );
    }

    sub h41_decr {
        my $s = shift;
        my $to;
        my $ts;
        my @ostr;
        my @q =
          ( ${$s} =~
/\xc6\x04\x24(.)|\xc6\x44\x24([\x00-\x7f].)|\xc6\x84\x24(..\x00\x00.)/g
          );
        my %ostr;
        my @l;
        for (@q) {
            next unless $_;
            my $o;
            my $c;
            my @q = split //;
            if    ( 2 == length $_ ) { $o = $q[0];  $c = $q[1] }
            elsif ( 1 == length $_ ) { $o = "\x00"; $c = $q[0] }
            else                     { $o = $q[0];  $c = $q[-1] }
            $o = ord $o;

            # 'aeiouy' 'bcdfghklmnprstvzx' standart strings
            if ( $o != $to + 1 ) {
                if ( $ts and length $ts > 4 ) {
                    push @ostr, $ts
                      unless $ts =~
                      /^\x61\x65\x69\x6f\x75|\x62\x63\x64\x66\x67/;
                }
                $ts = $c;
                $to = $o;
            }
            else { $ts .= $c; $to++ }
        }
        for (@ostr) { $_ = h41_decr1($_) }
        for (@ostr) { $ostr{$_}++ }
        print "mod_ssh41_cstr: " . join( '|', sort keys %ostr ) . "\n";
        for ( keys %ostr ) { push @l, $_ if m|^/| }
        ssh_ls(@l);
    }

    @sd = gs( '%s %s:%s', '-B 1' );
    @sc = gc( '%s %s:%s', '-B 1' );
    if ( f $sd[0] ) {
        print "mod_sshd41: '$sd[1]' '$sd[0]', crypted\n";
        h41_decr( \$bsshd );
    }
    if ( f $sc[0] ) {
        print "mod_sshc41: '$sc[1]' '$sc[0]', crypted\n";
        h41_decr( \$bssh );
    }

    @sd = gs('^in: %s \t: %s \t: %s$');
    @sc = gc('^out: %s \t: %s \t: %s$');
    if ( @sd || @sc ) {
        print "mod_sshd42: detected; log_useragent:passwd_file:passwd\n" if @sd;
        print "mod_sshc42: detected\n"                                   if @sc;
        ssh_ls();
    }

    @sd = gs( '%s:%s', '-A 1' );
    @sc = gc('%s -> %s:%s\@%s');
    if ( $sd[1] =~ m|^GET | ) {
        my @s = gs( 'dont', '-A 3' );
        my $k;
        $k = 1
          if ( $s[0] eq 'dontxekm' and $s[1] eq 'buygod.n' )
          or ( $s[0] eq 'dont' and $s[2] eq 'buyg' );
        printf "mod_sshd43: detected; known: %d\n", $k;
        ssh_ls();
    }
    if (@sc) {
        my @s = gc( 'dont', '-A 3' );
        my $k;
        $k = 1
          if ( $s[0] eq 'dontxekm' and $s[1] eq 'buygod.n' )
          or ( $s[0] eq 'dont' and $s[2] eq 'buyg' );
        printf "mod_sshc43: detected; known: %d\n", $k;
        ssh_ls();
    }
    @sd = gs( 'pass_from: %s ', '-B 2' );
    @sc = gc( 'Sniffed -> %s ', '-A 13' );
    if ( f $sd[0] ) {
        print "mod_sshd44: pass:'$sd[1]' '$sd[0]', '$sd[2]'\n";
        ssh_ls( $sd[0] );
    }
    if ( $sc[0] ) { print "mod_sshc44: '$sc[0]' '$sc[13]'\n"; ssh_ls( $sd[0] ) }
    @sd = gs( 'in:%s:%d:%s:%s:secret_%s', '-B 2' );
    @sc = gc( 'out::%s::%s:%d:%s:%s', '-B 1' );
    if ( $sd[0] ) {
        print "mod_sshd45: pass:'$sd[1]' host:'$sd[0]', '$sd[2]'\n";
        ssh_ls();
    }
    if ( $sc[0] ) { print "mod_sshc45: host:'$sc[0]' '$sc[1]'\n"; ssh_ls() }
    @sd = gs( 'SSH-1.5-W1.0', '-A 4' );
    @sc = gs( 'mkdir -p %s',  '-A 2' );
    if ( @sd && $sd[1] !~ /^SSH-/ ) {
        print "mod_sshd46: crypt:'$sc[1]' v1:'$sd[1]' v2:'$sd[2]'\n";
        ssh_ls('/usr/include/mbstring.h');
    }
    @sd = gs( 'user:password --> \|%s\|%s', '-B 2' );
    @sc = gc( 'user:password\@host --> \|%s\|%s\|%s', '-B 46' );
    if ( f $sd[1] ) {
        print "mod_sshd47: pass:'$sd[0]' '$sd[1]', '$sd[2]'\n";
        ssh_ls( $sd[1] );
    }
    if (@sc) { print "mod_sshc47: host:'$sc[0]' '$sc[-1]'\n"; ssh_ls( $sc[0] ) }

    #@sd=gs();@sc=gc();

    @sd = ();
    @sc = ();
    for (@bsshd) { push @sd, $_ if /^[0-9a-f]{32}$/ }
    for (@bssh)  { push @sc, $_ if /^[0-9a-f]{32}$/ }
    for (@sd)    { print "mod_md5_sshd: '$_'\n" }
    for (@sc)    { print "mod_md5_ssh: '$_'\n" }
    my $static_ssl;
    for (@sd) {
        $static_ssl++
          if $_ eq 'cf5ac8395bafeb13c02da292dded7a83'
          or $_ eq '27b6916a894d3aee7106fe805fc34b44';
    }
    print "mod_md5_static_ssl: $static_ssl\n" if $static_ssl;

    my @phs = (
        'HISTFILE', 'GET ',    '/tmp/sess_', 'UPX',
        'skynet',   'libcurl', ' \+password: '
    );
    my %idx;
    undef %idx;
    for (@phs) {
        my $s = $_;
        for ( 0 .. ( scalar @bsshd ) - 1 ) {
            $idx{ $bsshd[$_] }++ if $bsshd[$_] =~ /$s/;
        }
    }
    @sd = keys %idx;
    undef %idx;
    for (@phs) {
        my $s = $_;
        for ( 0 .. ( scalar @bssh ) - 1 ) {
            $idx{ $bssh[$_] }++ if $bssh[$_] =~ /$s/;
        }
    }
    @sc = keys %idx;
    if (@sd) {
        print "mod_hack_strd: possible hacked, " . join( "|", @sd ) . "\n";
        ssh_ls();
    }
    if (@sc) {
        print "mod_hack_strc: possible hacked, " . join( "|", @sc ) . "\n";
        ssh_ls();
    }

    @al = ( $bsshd =~ /\xc6\x45([\x80-\xff][\x00-\xff])/g );
    my @r1 = get_stack_strings( \@al );
    @al =
      ( $bsshd =~
/\xc6\x44\x24([\x00-\x7f][\x00-\xff])|\xc6\x84\x24([\x00-\xff][\x00-\x10]\x00\x00[\x00-\xff])/g
      );
    my @r2 = get_stack_strings( \@al );
    @al = ( $bsshd =~ /\xc6\x05([\x00-\xff]{5})/g );
    my @r3 = get_stack_strings( \@al );
    my @r4 = get_strings1( \@al );
    @sd = ();
    for ( @r1, @r2, @r3, @r4 ) { push @sd, $_ if /^[0-9a-f]{32}$/ }
    for (@sd) { print "mod_md5_sshd1: '$_'\n" }

    sub get_stack_strings {
        my $a  = shift;
        my $to = 0;
        my $ts = '';
        my @ostr;
        my %ostr;
        my @ss =
          qw{ mkdir var aeiouy bcdfghklmnprstvzx bcdfghklmnprstvz 000 aeiouybcdfg hklmnprstv aeiouybcdfghklmnprstvzx klmnprstvzx bcdfg rstvzx bcdfghklmn \000 };
        for ( @{$a} ) {
            next unless $_;
            my @q = split //;
            my $c = $q[-1];
            my $o = ord $q[0];
            if ( $o != $to + 1 ) {
                push @ostr, $ts if length $ts > 2;
                $ts = '';
                $to = $o;
                $ts .= $c;
                next;
            }
            $to++;
            if ( 0 == ord $c ) { push @ostr, $ts if length $ts > 2; $ts = '' }
            else               { $ts .= $c }
        }
        for (@ostr) { $ostr{$_}++ }
        for (@ss)   { delete $ostr{$_} }
        if ( keys %ostr ) {
            print "mod_str_sshd_str: '" . join( "':'", keys %ostr ) . "'\n";
            ssh_ls();
        }
        for ( keys %ostr ) { ssh_ls($_) if m|^/| }
        my @l = ( grep /^\//, keys %ostr );
        map s|\s||sg, @l;
        ssh_ls(@l) if @l;
        return ( keys %ostr );
    }

    sub get_strings1 {
        my $a  = shift;
        my $to = 0;
        my $ts = '';
        my @ostr;
        my %ostr;
        for ( @{$a} ) {
            next unless $_;
            my ( $o, $c ) = unpack( "LC", $_ );
            $c = chr $c;
            if ( $to > $o && $to - $o <= 20 && 0 != ord $c ) { $ts .= $c }
            else { push @ostr, $ts if length $ts > 3; $ts = $c }
            $to = $o;
        }
        for (@ostr) { $ostr{$_}++ }
        if ( keys %ostr ) {
            print "mod_str_sshd_str1: '" . join( "':'", keys %ostr ) . "'\n";
            ssh_ls();
        }
        for ( keys %ostr ) { ssh_ls($_) if m|^/| }
        my @l = ( grep /^\//, keys %ostr );
        map s|\s||sg, @l;
        ssh_ls(@l) if @l;
        return ( keys %ostr );
    }

    my @phsg =
      qw (/bin/login /bin/sh /dev/ /dev/net/tun /dev/null /dev/tty /etc/hosts.equiv /etc/motd /etc/nologin /etc/ssh/moduli /etc/ssh/primes
      /etc/ssh/shosts.equiv /etc/ssh/sshd_config /etc/ssh/ssh_host_dsa_key /etc/ssh/ssh_host_key /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_known_hosts
      /etc/ssh/ssh_known_hosts2 /lib/ld-linux.so.2 /nonexist /proc/%ld/fd /tmp/ssh-XXXXXXXXXX /tmp/.X11-unix/X%u /usr/bin:/bin:/usr/sbin:/sbin
      /usr/bin/passwd /usr/bin/xauth /usr/libexec/ssh-askpass /var/empty/sshd /var/log/btmp /var/log/lastlog /var/mail /var/run/sshd.mm.XXXXXXXX
      /var/run/sshd.pid /proc/self/oom_adj /usr/local/bin:/usr/bin:/bin:/usr/bin/X11:/usr/games /usr/share/ssh/blacklist /usr/bin/ssh-askpass
      /ssh /var/run/sshd /run /etc/ssh/blacklist /var /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/bin/X11 /lib64/ld-linux-x86-64.so.2
      /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
      /etc/ssh/ssh_host_ecdsa_key /tmp/ssh-XXXXXXXXXXXX /tmp/ssh-XXXXXXXX /usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin /etc/ssh/ssh_config /tRH
      /usr/lib/openssh/ssh-keysign /dev/random /dev/urandom /usr/libexec/openssh/ssh-keysign /sshd.mmH /var/runH /proc/self/oom_score_adj /sYL /siL /fff
      /usr/bin/X11/xauth /usr/X11R6/bin/xauth /usr/local/bin:/bin:/usr/bin /usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin /5r! /sshd.mm
      /usr/libexec/openssh/ssh-askpass /var/empty /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/bin/X11:/usr/games /tQH /var/run /t%H
      /org/freedesktop/ConsoleKit/Manager /wIL /primary /krb5cc_L /usr/share/dracut/modules.d/01fips /9l$ /etc/ssh/ssh_host_ed25519_key /L;d$ //G$ /~LD
      /etc/system-fips /usr/bin/login /usr/local/bin:/usr/bin /primaryH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin /tmp /=p0 /a4j$ /Qu6H /mRB
      /O&. /}QR
    );
    push @phsg, '/bin/sh /etc/ssh/sshrc', '/t H', '/t"H', '/n[(', '/Cd`',
      '/(_:', '/>;+"<Kq[e', '/h#!XM|/:B[9d';

    undef %idx;
    for ( 0 .. ( scalar @bsshd ) - 1 ) { $idx{ $bsshd[$_] }++ if f $bsshd[$_] }
    for (@phsg) { delete $idx{$_} }
    @sd = keys %idx;
    if (@sd) { print "sshd_str: " . join( '|', @sd ) . "\n" }
    undef %idx;
    for ( 0 .. ( scalar @bssh ) - 1 ) { $idx{ $bssh[$_] }++ if f $bssh[$_] }
    for (@phsg) { delete $idx{$_} }
    @sc = keys %idx;
    if (@sc) { print "sshc_str: " . join( '|', @sc ) . "\n" }

    # one byte xored path
    my @dir =
      qw { /bin /boo /dev /etc /hom /lib /los /med /mnt /opt /pro /roo /sbi /sys /tmp /usr /var };
    my %dir;
    for (@dir) { $dir{$_} = 1 }
    my @xbin1 = split( /\0/, $bsshd );
    my %decr;
    foreach my $q (@xbin1) {
        next if length $q < 6;
        my $s = substr( $q, 0, 1 );
        next if index( $q, $s, 1 ) < 2;
        next if $s eq '/';
        my $x = $s ^ '/';
        my $u = $q ^ $x x length $q;
        next if not exists $dir{ substr( $u, 0, 4 ) };
        push @{ $decr{ ord $x } }, $u;
    }
    for ( keys %decr ) {
        printf "mod_ssh_crypt: 0x%02x: %s\n", $_, join( '|', @{ $decr{$_} } );
        ssh_ls( @{ $decr{$_} } );
    }

}

check_binary();
for ( keys %pw ) { dump_passwd($_) }
