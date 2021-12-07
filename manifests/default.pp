#class { 'os_hardening': }

class { 'ssh_hardening::client': }
class { 'ssh_hardening::server':
  use_pam => true,
  pam_auth => true,
  ports => 20002,
}
