package TplinkSmarthome;

## TplinkSmarthome
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

sub send_data {
  my ( $host, $data ) = @_;

  ## Static info
  my $port = 9999;
  my $pack_tmpl = 'S n a4 x8';

  ## Get protocol info from OS (only needs to happen once)
  state $proto = ( getprotobyname 'tcp' )[2];

  ## Look up the host
  my @host_info = gethostbyname $host;
  die "Lookup of host $host failed"
    if @host_info < 5;

  ## We only care about specifying the remote port; there is no need to
  ##   BIND the socket to a local port
  my $remote = pack $pack_tmpl, AF_INET, $port, $host_info[4];
  socket my $connection, AF_INET, SOCK_STREAM, $proto
    or die "socket failed ($!)";

  ## Create the actual connection
  connect $connection, $remote
    or die "Failed to connect to $host ($!)";

  ## Disable buffering on the socket
  my $old_default = select $connection;
  $| = 1;
  select $old_default;

  ## Enable binmode (obfuscation makes data binary)
  binmode $connection;

  ## Send the obfuscated JSON message
  print $connection _obfuscate( encode_json $data );

  ## Get an obfuscated JSON reply
  # XXX In the python, I think this read exactly 2048 bytes
  my $reply = <$connection>;

  ## These connections cannot be re-used
  close $connection;

  ## Return reply as a data structure
  return decode_json _clarify( $reply );
  }

sub _obfuscate {
  my ( $string ) = @_;
  my $key = 171;
  my @obfuscated = map { chr }
                   map { $key = $key ^ ord $_ }
                   split //, $string;
  ## Add four leading null bytes
  return join '', "\0\0\0\0", @obfuscated;
}

sub _clarify {
  my ( $string ) = @_;
  ## Remove four leading null bytes
  $string = substr $string, 4;
  my $key = 171;
  my @clarified = map { chr }
                  map { my $old_key = $key; $key = ord $_; $old_key ^ ord $_ }
                  split //, $string;
  return join '', @clarified;
}

1; ## Exit non-zero
