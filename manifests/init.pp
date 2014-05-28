# == Define: Account
#
# A defined type for managing user accounts
# Features:
#   * Account creation w/ UID control
#   * Setting the login shell
#   * Group creation w/ GID control (optional)
#   * Home directory creation ( and optionally management via /etc/skel )
#   * Support for system users/groups
#   * SSH key management (optional)
#
# === Parameters
#
# [*ensure*]
#   The state at which to maintain the user account.
#   Can be one of "present", "deactivate", "absent", or "purge".
#   Absent will remove the user but leave the home directory
#   Purge  will remove the user and purge the home directory
#   Deactivate will set shell to "false" to disable user to connect and leave the home directory.
#   Defaults to present.
#
# [*username*]
#   The name of the user to be created.
#   Defaults to the title of the account resource.
#
# [*uid*]
#   The UID to set for the new account.
#   If set to undef, this will be auto-generated.
#   Defaults to undef.
#
# [*password*]
#   The password to set for the user.
#   The default is to disable the password.
#
# [*shell*]
#   The user's default login shell.
#   The default is '/bin/bash'
#
# [*manage_home*]
#   Whether the underlying user resource should manage the home directory.
#   This setting only determines whether or not puppet will copy /etc/skel.
#   Regardless of its value, at minimum, a home directory and a $HOME/.ssh
#   directory will be created. 
#   This will create the home directory when ensure => present, and delete
#   the home directory when ensure => absent. Defaults to true.
#
# [*home_dir*]
#   The location of the user's home directory.
#   Defaults to "/home/$title".
#
# [*create_group*]
#   Whether or not a dedicated group should be created for this user.
#   If set, a group with the same name as the user will be created.
#   Otherwise, the user's primary group will be set to "users".
#   Defaults to true.
#
# [*groups*]
#   An array of additional groups to add the user to.
#   Defaults to an empty array.
#
# [*system*]
#   Whether the user is a "system" user or not.
#   Defaults to false.
#
# [*ssh_key*]
#   A string containing a public key suitable for SSH logins
#   If set to 'undef', no key will be created.
#   Defaults to undef.
#
# [*ssh_key_type*]
#   The type of SSH key to manage. Accepts any value accepted by
#   the ssh_authorized_key's 'type' parameter.
#   Defaults to 'ssh-rsa'.
#
# [*ssh_keys*]
#   A hash of SSH key data in the following form:
#     { key1 => { type => 'ssh-rsa', key => 'AAAZZZ...' } }
#
# [*comment*]
#   Sets comment metadata for the user
#
# [*gid*]
#   Sets the primary group of this user, if $create_group = false
#   Defaults to 'users'
#     WARNING: Has no effect if used with $create_group = true
#
# [*allowdupe*]
#   Whether to allow duplicate UIDs.
#   Defaults to false.
#   Valid values are true, false, yes, no.
# [*sudo*]
#   Set sudo privilege to user.
#   Default to false.
#   Valid values are true, false.
#
# === Examples
#
#  account { 'sysadmin':
#    home_dir => '/opt/home/sysadmin',
#    groups   => [ 'sudo', 'wheel' ],
#  }
#
# === Authors
#
# Tray Torrance <devwork@warrentorrance.com>
#
# === Copyright
#
# Copyright 2013 Tray Torrance, unless otherwise noted
#
define account(
  $username = $title,
  $password = '!',
  $shell = '/bin/bash',
  $home_dir = undef,
  $home_dir_perms = '0755',
  $create_group = true,
  $system = false,
  $uid = undef,
  $ssh_key = undef,
  $ssh_key_type = 'ssh-rsa',
  $groups = [],
  $ensure = present,
  $comment= "${title} Puppet-managed User",
  $gid = 'users',
  $allowdupe = false,
  $ssh_keys = undef,
  $sudo = false,
) {

  if $home_dir == undef {
    if $username == 'root' {
      case $::operatingsystem {
        'Solaris': { $home_dir_real = '/' }
        default:   { $home_dir_real = '/root' }
      }
    }
    else {
      case $::operatingsystem {
        'Solaris': { $home_dir_real = "/export/home/${username}" }
        default:   { $home_dir_real = "/home/${username}" }
      }
    }
  }
  else {
      $home_dir_real = $home_dir
  }

  case $ensure {
    present: {
      $dir_ensure = directory
      $dir_owner  = $username
      $dir_group  = $primary_group
      $dir_force  = false
      $file_ensure = $ensure
      $group_ensure = $ensure
      $user_ensure = $ensure
      $shell_ensure = $shell
      $ssh_key_owner = $username
      $sudo_real = true
      User[$title] -> File["${title}_home"] -> File["${title}_sshdir"]
    }
    deactivate: {
      $dir_ensure = directory
      $dir_owner  = $username
      $dir_group  = $primary_group
      $dir_force  = false
      $file_ensure = present
      $group_ensure = present
      $user_ensure = present
      $shell_ensure = '/bin/false'
      $ssh_key_owner = $username
      $sudo_real = false
      User[$title] -> File["${title}_home"] -> File["${title}_sshdir"]
    }
    absent: {
      $dir_ensure = directory
      $dir_owner  = 'root'
      $dir_group  = 'root'
      $dir_force  = false
      $file_ensure = $ensure
      $group_ensure = $ensure
      $user_ensure = $ensure
      $ssh_key_owner = 'root'
      $sudo_real = false
      File["${title}_sshdir"] -> File["${title}_home"] -> User[$title]
    }
    purge: {
      $dir_ensure = absent
      $dir_force  = true
      $file_ensure = absent
      $group_ensure = absent
      $user_ensure = absent
      $ssh_key_owner = $username
      $sudo_real = false
      File["${title}_sshdir"] -> File["${title}_home"] -> User[$title]
    }
    default: {
      err( "Invalid value given for ensure: ${ensure}. Must be one of present|deactivate|absent|purge." )
    }
  }

  if $create_group == true {
    $primary_group = $username

    group {
      $title:
        ensure => $group_ensure,
        name   => $username,
        system => $system,
        gid    => $uid,
    }

    case $group_ensure {
      present: {
        Group[$title] -> User[$title]
      }
      absent: {
        User[$title] -> Group[$title]
      }
      default: {}
    }
  }
  else {
    $primary_group = $gid
  }


  user {
    $title:
      ensure     => $user_ensure,
      name       => $username,
      comment    => $comment,
      uid        => $uid,
      password   => $password,
      shell      => $shell_ensure,
      gid        => $primary_group,
      groups     => $groups,
      home       => $home_dir_real,
      managehome => false,
      system     => $system,
      allowdupe  => $allowdupe,
  }

  file {
    "${title}_home":
      ensure => $dir_ensure,
      path   => $home_dir_real,
      owner  => $dir_owner,
      group  => $dir_group,
      mode   => $home_dir_perms,
      force  => $dir_force;

    "${title}_sshdir":
      ensure => $dir_ensure,
      path   => "${home_dir_real}/.ssh",
      owner  => $dir_owner,
      group  => $dir_group,
      mode   => '0700',
      force  => $dir_force;
  }

  if $ssh_key != undef {
    warning('The "ssh_key" setting of the "account" type has been deprecated in favor of "ssh_keys"! Check the docs and upgrade ASAP.')

    ssh_authorized_key {
      $title:
        ensure  => $file_ensure,
        type    => $ssh_key_type,
        name    => "${title} SSH Key",
        user    => $ssh_key_owner,
        key     => $ssh_key,
    }
  }

  if $ssh_keys != undef {
    $ssh_key_settings = {
      ensure => $file_ensure,
      user   => $username,
    }
    create_resources('ssh_authorized_key', $ssh_keys, $ssh_key_settings)
  }

  validate_bool($sudo)

  if ($sudo and $sudo_real) {
    sudo::conf { $username:
        ensure => present,
        content => "${username} ALL=(ALL) NOPASSWD: ALL",
    }
  }
  else {
    sudo::conf { $username:
        ensure => absent,
    }
  }

}

