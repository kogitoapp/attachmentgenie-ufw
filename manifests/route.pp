#  Installs and enables Ubuntu's "uncomplicated" firewall.
#
#  Be careful calling this class alone, it will by default enable ufw
# and disable all incoming traffic.
#
#
# @example when declaring the ufw class
#  ufw::route { 'route-from-eth0-to-eth1':
#    interface_in  => 'eth0',
#    interface_out => 'eth1',
#  }
#
# @param ensure Enable of disable rule. default: present
# @param action Action to perform. default: reject
# @param interface_in Interface that recieves traffic.
# @param interface_out Interface that sends traffic.
# @param log Logging option
# @param proto Protocol
# @param from_addr Source address. default: any
# @param from_port_app Source address port or app.
# @param to_addr Destination address. default: any
# @param to_port_app Destination address port or app.
define ufw::route(
  Enum['present', 'absent']                      $ensure        = present,
  Enum['allow','deny','reject', 'limit']         $action        = 'reject',
  Optional[String]                               $interface_in  = undef,
  Optional[String]                               $interface_out = undef,
  Optional[Enum['log', 'log-all']]               $log           = undef,
  Optional[Enum['tcp','udp','any']]              $proto         = undef,
  Optional[Variant[Stdlib::IP::Address, String]] $from_addr     = 'any',
  Optional[Variant[Stdlib::Port, String]]        $from_port_app = undef,
  Optional[Variant[Stdlib::IP::Address, String]] $to_addr       = 'any',
  Optional[Variant[Stdlib::Port, String]]        $to_port_app   = undef,
) {
  $in_definition = $interface_in ? {
    undef => undef,
    default => "in on ${interface_in}",
  }

  $out_definition = $interface_out ? {
    undef => undef,
    default => "out on ${interface_out}"
  }

  $proto_definition = $proto ? {
    'tcp' => 'proto tcp',
    'udp' => 'proto udp',
    default => undef #in case of "any", ufw omits it
  }

  $from_definition = "${from_addr}:${from_port_app}" ? {
    'any:'     => undef, # "any" is only needed if port or app are specified, otherwise ufw omits it
    /:$/       => "from ${from_addr}",
    /:[0-9]+$/ => "from ${from_addr} port ${from_port_app}",
    /:\w+$/    => "from ${from_addr} app ${from_port_app}",
    default    => fail('from_addr is required when from_port_app is specified')
  }

  $to_definition = "${to_addr}:${to_port_app}" ? {
    'any:'     => undef, # "any" is only needed if port or app are specified, otherwise ufw omits it
    /:$/       => "to ${to_addr}",
    /:[0-9]+$/ => "to ${to_addr} port ${to_port_app}",
    /:\w+$/    => "to ${to_addr} app ${to_port_app}",
    default    => fail('to_addr is required when to_port_app is specified')
  }

  $params = [$action, $in_definition, $out_definition, $log, $proto_definition, $from_definition, $to_definition].filter |$item| { $item }
  $add_command = "ufw route ${join($params, ' ')}"

  if $ensure == 'present' {
    exec { $add_command:
      path     => '/usr/sbin:/bin:/usr/bin',
      provider => 'posix',
      unless   => "ufw show added | grep -q '${add_command}'",
      require  => Exec['ufw-default-deny'],
      before   => Exec['ufw-enable'],
    }
  } else {
    exec { "ufw route delete ${join($params, ' ')}":
      path     => '/usr/sbin:/bin:/usr/bin',
      provider => 'posix',
      onlyif   => "ufw show added | grep -q '${add_command}'",
      require  => Exec['ufw-default-deny'],
      before   => Exec['ufw-enable'],
    }
  }
}
