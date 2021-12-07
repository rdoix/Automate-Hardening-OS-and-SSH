# Hardening base on your OS
class { 'os_hardening': }

# Hardening SSH Client
class { 'ssh_hardening::client': }

#Hardening SSH Server, in this case enable and allowed to use password authentication, and SSH port is 20002
class { 'ssh_hardening::server':
  use_pam => true, 
  pam_auth => true,
  ports => 20002,
}
