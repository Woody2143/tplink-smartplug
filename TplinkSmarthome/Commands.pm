package TplinkSmarthome::Commands;

## TplinkSmarthome::Commands
##   Copyright (c) 2016 softScheck GmbH, released under the Apache 2.0 license
##   Copyright (c) 2016 Stephen Cristol, released under the Apache 2.0 license
##
## This project is a fork of "TP-Link WiFi SmartPlug Client and
## Wireshark Dissector" by Lubomir Stroetmann [1]. softScheck Gmbh has a
## nice article ("Reverse Engineering the TP-Link HS110") describing the
## work behind the original project [2]. To get the most from this or
## the original project, I strongly recommend reading that article.
## Others have also written code based on the original project [3] or on
## their own work [4].
##
## The primary purpose of this fork is to convert the code from Python
## to Perl. I am intentionally removing the Python file, the Lua file
## (and its related PNG file), and the tddp-client directory as I will
## not be modifying or maintaining them at this time.
##
## This is an adaption rather than a literal translation from Python to
## Perl. I have also divided this into a module and a sample client.
##
## [1] https://github.com/softScheck/tplink-smartplug
## [2] https://www.softscheck.com/en/reverse-engineering-tp-link-hs110/
## [3] https://github.com/GadgetReactor/pyHS100
## [4] https://georgovassilis.blogspot.sg/2016/05/controlling-tp-link-hs100-wi-fi-smart.html
##
## Following is the description, copyright notice, and license from the
## original project:
##
## TP-Link Wi-Fi Smart Plug Protocol Client
## For use with TP-Link HS-100 or HS-110
##
## by Lubomir Stroetmann
## Copyright 2016 softScheck GmbH
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##      http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.

use 5.010;
use warnings;

use Socket;
use JSON::XS;

use TplinkSmarthome;

## Predefined commands
my %command = (
	antitheft     => { anti_theft => { get_rules       => {}               } },
	cloudinfo     => { cnCloud    => { get_info        => {}               } },
	countdown     => { count_down => { get_rules       => {}               } },
  info          => { system     => { get_sysinfo     => {}               } },
	off           => _set_relay_state( 0 ),
	on            => _set_relay_state( 1 ),
	relay         => \&_set_relay_state,
	reboot        => { system     => { reboot          => { delay   => 1 } } },
	reset         => { system     => { reset           => { delay   => 1 } } },
	schedule      => { schedule   => { get_rules       => {}               } },
	time          => { time       => { get_time        => {}               } },
	wlanscan      => { netif      => { get_scaninfo    => { refresh => 1 } } },
	meter_now     => { emeter     => { get_realtime    => {}               } },
	meter_daily   => \&_get_daystat,
	meter_monthly => \&_get_monthstat,
  );

sub list_commands {
  return keys %command;
}

sub send_command {
  my ( $host, $cmd, @params ) = @_;
  die qq{"$cmd" is not a pre-defined command}
    if ! exists $command{$cmd};
  return TplinkSmarthome::send_data( $host, _get_command( $cmd, @params ) );
}

sub _get_command {
  my ( $cmd, @params ) = @_;
  my $comm = $command{$cmd};
  $comm = &$comm( @params )
    if ref $comm eq 'CODE';
  return $comm;
}

sub _set_relay_state {
  my ( $state ) = @_;
  $state = _bin_state( 'Relay', $state );
  return { system => { set_relay_state => { state => $state } } };
}

sub _get_daystat {
  my ( $mon, $year ) = @_;
  ( $mon, $year ) = ( _now() )[ 4, 5 ]
    if ! defined $year;
  return { emeter => { get_daystat => { month => $mon, year => $year } } };
}

sub _get_monthstat {
  my ( $year ) = @_;
  ( $year ) = ( _now() )[ 5 ]
    if ! defined $year;
  return { emeter => { get_monthstat => { year => $year } } };
}

## This is used to determine whether to turn electricity on or off.
## Be persnickety. Default to off.
sub _bin_state {
  my ( $descriptor, $state ) = @_;
  return 0
    if ! defined $state || $state eq '0';
  $state = lc $state;
  return 0
    if $state eq 'off' || $state eq 'f' || $state eq 'false';
  return 1
    if $state eq '1' || $state eq 'on' || $state eq 't' || $state eq 'true';
  die "$descriptor state must be 0/off/f/false or 1/on/t/true (case insensitive)"
}

## Provide all the elements from localtime
sub _now {
  my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) =
    localtime;
  $mon  +=    1;
  $year += 1900;
  return ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst )
}

1; ## Exit non-zero
