# Class to manage ufw parameters.
#
# Dont include this class directly.
#
class ufw::params (
  Hash                                      $allow          = {},
  Hash                                      $deny           = {},
  Boolean                                   $deny_outgoing  = false,
  Enum['ACCEPT','DROP','REJECT']            $forward        = 'DROP',
  Hash                                      $limit          = {},
  Enum['off','low','medium','high','full']  $log_level      = 'low',
  Boolean                                   $manage_service = true,
  Hash                                      $reject         = {},
  String                                    $service_name   = 'ufw',
  Hash                                      $route          = {},
  ) {
}
