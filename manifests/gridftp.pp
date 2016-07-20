class creamce::gridftp inherits creamce::params {

  require creamce::yumrepos
  require creamce::certificate
  
  $config_glexec = false
    
  if $use_argus == "true" {
    $gridftp_auth_plugin = "argus-gsi-pep-callout"
  } else {
    $gridftp_auth_plugin = "lcas-lcmaps-gt4-interface"
    require creamce::glexec
  }
  
  class{ "gridftp::install":}
  
  class{ "gridftp::service":}
  
  class{ "gridftp::config":
    require => Package["globus-proxy-utils", "kill-stale-ftp", "${gridftp_auth_plugin}"],
    notify  => Class[Gridftp::Service],
  }
  
  if $use_argus == "true" {
  
    file { "/etc/grid-security/gsi-authz.conf":
      ensure  => file,
      owner   => "root",
      group   => "root",
      mode    => 0644,
      content => "globus_mapping /usr/lib64/libgsi_pep_callout.so argus_pep_callout\n",
      require => Class[Gridftp::Config],
      notify  => Class[Gridftp::Service],
    }
  
    file { "/etc/grid-security/gsi-pep-callout.conf":
      ensure  => file,
      owner   => "root",
      group   => "root",
      mode    => 0644,
      content => "pep_ssl_server_capath ${cacert_dir}
pep_ssl_client_cert ${host_certificate}
pep_ssl_client_key ${host_private_key}
pep_timeout 30
xacml_resourceid ${cream_pepc_resourceid}
pep_url https://${argusservice}:${argusport}/authz
",
      require => Class[Gridftp::Config],
      notify  => Class[Gridftp::Service],
    }

  } else {
  
    file { "/etc/lcas/lcas.db":
      ensure  => file,
      owner   => "root",
      group   => "root",
      mode    => 0644,
      content => template("creamce/lcas-glexec.db.erb"),
    }

    file { "/etc/lcas/ban_users.db":
      ensure  => file,
      owner   => "root",
      group   => "root",
      mode    => 0644,
      content => "# Banned users\n",
    }

    file {"/etc/lcmaps/lcmaps.db":
      ensure => present,
      content => template("creamce/lcmaps-glexec.db.erb"),
      owner => "root",
      group => "root",
      mode => 0640,
    }

    file { "/etc/grid-security/gsi-authz.conf":
      ensure  => file,
      owner   => "root",
      group   => "root",
      mode    => 0644,
      content => "globus_mapping /usr/lib64/liblcas_lcmaps_gt4_mapping.so lcmaps_callout\n",
      require => Class[Gridftp::Config],
      notify  => Class[Gridftp::Service],
    }

  }
  
  package { ["globus-proxy-utils", "kill-stale-ftp", "${gridftp_auth_plugin}"]:
    ensure  => present,
    require => Class[Gridftp::Install],
  }
  
}
