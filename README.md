# Automate Hardening OS & SSH with Puppet


## Module Description

This Puppet module provides secure configuration of SSH & your base OS with hardening automatically

## Setup Congiuration

### Setup Requirements

* Puppet OpenSource or Enterprise Server (Linux)
* Git
* SSH
* [Module stdlib](https://forge.puppet.com/puppetlabs/stdlib)
* [Module sysctl](https://forge.puppet.com/herculesteam/augeasproviders_sysctl)

### Setup Hardening Modules

```bash
# Change to directory environments
cd /etc/puppetlabs/code/environments/production/
git clone https://github.com/rdoix/Puppet-Hardening.git .
```

### Sample Puppet Manifest
Create or edit file on `/etc/puppetlabs/code/environments/production/<file.pp>` and input the script
```puppet
class { 'os_hardening':
  enable_ipv4_forwarding => true,
  wanted_packages   => ['ntp'],
  unwanted_packages => ['telnet'],
  disabled_services => ['rsync'],
  
}

class { 'ssh_hardening::client': }

class { 'ssh_hardening::server':
  use_pam => true,
  pam_auth => true,
  ports => 20002,
  listen_to => 10.2.3.4
}
```

## Usage

### IMPORTANT for Puppet Enterprise

**If you are using this module in a PE environment, you have to set** `pe_environment = true`
Otherwise puppet will drop an error (duplicate resource)!

### SSH Hardening Parameters

* `ipv6_enabled = false`
  true if IPv6 is needed
* `cbc_required = false`
  true if CBC for ciphers is required. This is usually only necessary, if older M2M mechanism need to communicate with SSH, that don't have any of the configured secure ciphers enabled. CBC is a weak alternative. Anything weaker should be avoided and is thus not available.
* `weak_hmac`
  false - true if weaker HMAC mechanisms are required. This is usually only necessary, if older M2M mechanism need to communicate with SSH, that don't have any of the configured secure HMACs enabled.
* `weak_kex`
  false - true if weaker Key-Exchange (KEX) mechanisms are required. This is usually only necessary, if older M2M mechanism need to communicate with SSH, that don't have any of the configured secure KEXs enabled.
* `allow_root_with_key = false`
  false to disable root login altogether. Set to true to allow root to login via key-based mechanism.d
* `ports = [ 22 ]`
  ports to which ssh-server should listen to and ssh-client should connect to
* `listen_to = [ "0.0.0.0" ]`
  one or more ip addresses, to which ssh-server should listen to. Default is empty, but should be configured for security reasons!
* `remote_host`
  one or more hosts, to which ssh-client can connect to. Default is empty, but should be configured for security reasons!
* `allow_tcp_forwarding = false`
  set to true to allow TCP forwarding
* `allow_agent_forwarding = false`
  set to true to allow Agent forwarding
* `use_pam = false`
  to disable pam authentication
* `pam_auth = false`
  to disable Password Authentication

### OS Hardening Parameters

* `system_environment = 'default'`
  define the context in which the system runs. Some options don't work for `docker`/`lxc`
* `pe_environment = false`
  set this to true if you are using Puppet Enterprise **IMPORTANT - see above**
* `extra_user_paths = []`
  add additional paths to the user's `PATH` variable (default is empty).
* `umask = undef`
  umask used for the creation of new home directories by useradd / newusers (e.g. '027')
* `maildir = undef`
  path for maildir (e.g. '/var/mail')
* `usergroups = true`
  true if you want separate groups for each user, false otherwise
* `sys_uid_min = undef` and `sys_gid_min = undef`
  override the default setting for `login.defs`
* `password_max_age = 60`
  maximum password age
* `password_min_age = 7`
  minimum password age (before allowing any other password change)
* `password_warn_age = 7`
  Days warning before password change is due
* `login_retries = 5`
  the maximum number of login retries if password is bad (normally overridden by PAM / auth_retries)
* `login_timeout = 60`
  authentication timeout in seconds, so login will exit if this time passes
* `chfn_restrict = ''`
  which fields may be changed by regular users using chfn
* `allow_login_without_home = false`
  true if to allow users without home to login
* `allow_change_user = false`
  if a user may use `su` to change his login
* `ignore_users = []`
  array of system user accounts that should _not be_ hardened (password disabled and shell set to `/usr/sbin/nologin`)
* `folders_to_restrict = ['/usr/local/games','/usr/local/sbin','/usr/local/bin','/usr/bin','/usr/sbin','/sbin','/bin']`
  folders to make sure of that group and world do not have write access to it or any of the contents
* `ignore_max_files_warnings = false`
  true if you do not want puppet to log max_files and performance warnings on the recursion of folders with > 1000 files eg /bin /usr/bin
* `recurselimit = 5`
  directory depth for recursive permission check
* `passwdqc_enabled = true`
  true if you want to use strong password checking in PAM using passwdqc
* `auth_retries = 5`
  the maximum number of authentication attempts, before the account is locked for some time
* `auth_lockout_time = 600`
  time in seconds that needs to pass, if the account was locked due to too many failed authentication attempts
* `passwdqc_options = 'min=disabled,disabled,16,12,8'`
  set to any option line (as a string) that you want to pass to passwdqc
* `manage_pam_unix = false`
  true if you want pam_unix managed by this module
* `enable_pw_history = true`
  true if you want pam_unix to remember password history to prevent reuse of passwords (requires `manage_pam_unix = true`)
* `pw_remember_last = 5`
  the number of last passwords (e.g. 5 will prevent user to reuse any of her last 5 passwords)
* `only_root_may_su = false`
  true when only root and member of the group wheel may use su, required to be true for CIS Benchmark compliance
* `root_ttys = ['console','tty1','tty2','tty3','tty4','tty5','tty6']`
  registered TTYs for root
* `whitelist = []`
  all files which should keep their SUID/SGID bits if set (will be combined with pre-defined whiteliste of files)
* `blacklist = []`
  all files which should have their SUID/SGID bits removed if set (will be combined with pre-defined blacklist of files)
* `remove_from_unknown = false`
  `true` if you want to remove SUID/SGID bits from any file, that is not explicitly configured in a `blacklist`. This will make every Puppet run search through the mounted filesystems looking for SUID/SGID bits that are not configured in the default and user blacklist. If it finds an SUID/SGID bit, it will be removed, unless this file is in your `whitelist`.
* `dry_run_on_unknown = false`
  like `remove_from_unknown` above, only that SUID/SGID bits aren't removed. It will still search the filesystems to look for SUID/SGID bits but it will only print them in your log. This option is only ever recommended, when you first configure `remove_from_unknown` for SUID/SGID bits, so that you can see the files that are being changed and make adjustments to your `whitelist` and `blacklist`.
* `enable_module_loading = true`
  true if you want to allowed to change kernel modules once the system is running (eg `modprobe`, `rmmod`)
* `load_modules = []`
  load this modules via initramfs if enable_module_loading is false
* `disable_filesystems = ['cramfs','freevxfs','jffs2','hfs','hfsplus','squashfs','udf']`
  array of filesystems (kernel modules) that should be disabled
* `cpu_vendor = 'intel'`
  only required if `enable_module_loading = false`: set the CPU vendor for modules to load
* `icmp_ratelimit = '100'`
  default value '100', allow overwriting, needs String
* `desktop_enabled = false`
  true if this is a desktop system, ie Xorg, KDE/GNOME/Unity/etc
* `enable_ipv4_forwarding = false`
  true if this system requires packet forwarding in IPv4 (eg Router), false otherwise
* `manage_ipv6 = true`
  true to harden ipv6 setup, false to ignore ipv6 completely
* `enable_ipv6 = false`
  false to disable ipv6 on this system, true to enable
* `enable_ipv6_forwarding = false`
  true if this system requires packet forwarding in IPv6 (eg Router), false otherwise
* `arp_restricted = true`
  true if you want the behavior of announcing and replying to ARP to be restricted, false otherwise
* `arp_ignore_samenet = false`
  true will drop packets that are not from the same subnet (arp_ignore = 2), false will only check the target ip (arp_ignore = 1)
* `enable_sysrq = false`
  true to enable the magic sysrq key, false otherwise
* `enable_core_dump = false`
  false to prevent the creation of core dumps, true otherwise
* `enable_stack_protection = true`
  for Address Space Layout Randomization. ASLR can help defeat certain types of buffer overflow attacks. ASLR can locate the base, libraries, heap, and stack at random positions in a process's address space, which makes it difficult for an attacking program to predict the memory address of the next instruction.
* `enable_rpfilter = true`
  true to enable reverse path filtering (discard bogus packets), false otherwise
* `rpfilter_loose = false`
  (only if `enable_rpfilter` is true) *loose mode* (rp_filter = 2) if true, *strict mode* otherwise
* `enable_log_martians = true`
  true to enable logging on suspicious / unroutable network packets, false otherwise **WARNING - this might generate huge log files!**
* `unwanted_packages = []`
  packages that should be removed from the system
* `wanted_packages = []`
  packages that should be added to the system
* `disabled_services = []`
  services that should not be enabled
* `enable_grub_hardening = false`
  set to true to enable some grub hardening rules
* `grub_user = 'root'`
  the grub username that needs to be provided when changing config on the grub prompt
* `grub_password_hash = ''`
  a password hash created with `grub-mkpasswd-pbkdf2` that is associated with the grub\_user
* `boot_without_password = true`
  setup Grub so it only requires a password when changing an entry, not when booting an existing entry
* `system_umask = undef`
  if this variable is set setup the umask for all user in the system (e.g. '027')
* `manage_home_permissions = false`
  set to true to manage local users file and directory permissions (g-w,o-rwx)
* `ignore_home_users = []`
  array for users that is not to be restricted by manage_home_permissions
* `manage_log_permissions = false`
  set to true to manage log file permissions (g-wx,o-rwx)
* `restrict_log_dir = ['/var/log/']`
  set main log dir
* `ignore_restrict_log_dir = []`
  array to exclude log dirs under the main log dir
* `ignore_files_in_folder_to_restrict = []`
  array to ignore files to hardened in dirs under the folder_to_restrict array
* `manage_cron_permissions = false`
  set to true to manage cron file permissions (og-rwx)
* `enable_sysctl_config = true`
  set to false to disable sysctl configuration
* `manage_system_users = true`
  set to false to disable managing of system users (empty password and setting nologin shell)

_refrence and modified from_ [DevSec Hardening Framework](https://github.com/dev-sec)
