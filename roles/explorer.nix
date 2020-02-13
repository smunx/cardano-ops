{ config, name, lib, nodes, ... }:
with import ../nix {};

let
  nodeCfg = config.services.cardano-node;
  iohkNix = import sourcePaths.iohk-nix {};
  cardano-sl = import sourcePaths.cardano-sl { gitrev = sourcePaths.cardano-sl.rev; };
  explorerFrontend = cardano-sl.explorerFrontend;
  postgresql12 = (import sourcePaths.nixpkgs-postgresql12 {}).postgresql_12;
  nodeId = config.node.nodeId;
  hostAddr = getListenIp nodes.${name};
  loggerConfig = import ../modules/iohk-monitoring-config.nix // {
    hasPrometheus = [ "127.0.0.1" 12797 ];
    hasEKG = 12798;
  };
  # We need first 3 signing keys and delegation certificate
  # to be able to run tx generator and sign generated transactions.
  signingKeyGen = ../keys/delegate-keys.000.key;
  signingKeySrc = ../keys/delegate-keys.001.key;
  signingKeyRec = ../keys/delegate-keys.002.key;
  delegationCertificate = ../keys/delegation-cert.000.json;
in {
  imports = [
    (sourcePaths.cardano-node + "/nix/nixos")
    (sourcePaths.cardano-explorer + "/nix/nixos/cardano-exporter-service.nix")
    (sourcePaths.cardano-explorer + "/nix/nixos/cardano-tx-submitter.nix")
    (sourcePaths.cardano-explorer + "/nix/nixos/cardano-explorer-webapi.nix")
    (sourcePaths.cardano-explorer + "/nix/nixos/cardano-explorer-everything.nix")
    (sourcePaths.cardano-graphql + "/nix/nixos")
    ../modules/common.nix
  ];

  environment.systemPackages = with pkgs; [ bat fd lsof netcat ncdu ripgrep tree vim cardano-cli ];
  services.postgresql.package = postgresql12;

  services.graphql-engine.enable = true;
  services.cardano-graphql.enable = true;
  services.cardano-node = {
    enable = true;
    inherit nodeId;
    environment = globals.environmentName;
    # extraArgs = [ "+RTS" "-N2" "-A10m" "-qg" "-qb" "-M3G" "-RTS" ];
    environments = {
      "${globals.environmentName}" = globals.environmentConfig;
    };

    nodeConfig = globals.environmentConfig.nodeConfig // {
      hasPrometheus = [ hostAddr globals.cardanoNodePrometheusExporterPort ];
    };
  };
  # systemd.services.cardano-node.serviceConfig.MemoryMax = "3.5G";
  # TODO remove next two line for next release cardano-node 1.7 release:
  systemd.services.cardano-node.scriptArgs = toString nodeId;
  systemd.services.cardano-node.preStart = ''
    if [ -d ${nodeCfg.databasePath}-0 ]; then
      mv ${nodeCfg.databasePath}-0 ${nodeCfg.databasePath}
    fi
  '';

  users.users.cardano-node.extraGroups = [ "keys" ];

  deployment.keys = {
    "cardano-node-signing-gen" = builtins.trace ("${name}: using " + (toString signingKeyGen)) {
        keyFile = signingKeyGen;
        user = "cardano-node";
        group = "cardano-node";
        destDir = "/var/lib/keys";
    };
    "cardano-node-signing-src" = builtins.trace ("${name}: using " + (toString signingKeySrc)) {
        keyFile = signingKeySrc;
        user = "cardano-node";
        group = "cardano-node";
        destDir = "/var/lib/keys";
    };
    "cardano-node-signing-rec" = builtins.trace ("${name}: using " + (toString signingKeyRec)) {
        keyFile = signingKeyRec;
        user = "cardano-node";
        group = "cardano-node";
        destDir = "/var/lib/keys";
    };
    "cardano-node-delegation-cert" = builtins.trace ("${name}: using " + (toString delegationCertificate)) {
        keyFile = delegationCertificate;
        user = "cardano-node";
        group = "cardano-node";
        destDir = "/var/lib/keys";
    };
  };

  services.cardano-exporter = {
    enable = true;
    cluster = globals.environmentName;
    environment = globals.environmentConfig;
    socketPath = "/run/cardano-node/node-${toString nodeId}.socket"; # TODO: ref nodeCf.socketPath for next release (1.7)
    logConfig = iohkNix.cardanoLib.defaultExplorerLogConfig // { hasPrometheus = [ hostAddr 12698 ]; };
    #environment = targetEnv;
  };
  systemd.services.cardano-explorer-node = {
    wants = [ "cardano-node.service" ];
    serviceConfig.PermissionsStartOnly = "true";
    preStart = ''
      for x in {1..24}; do
        [ -S "${config.services.cardano-exporter.socketPath}" ] && break
        echo loop $x: waiting for "${config.services.cardano-exporter.socketPath}" 5 sec...
      sleep 5
      done
      chgrp cexplorer "${config.services.cardano-exporter.socketPath}"
      chmod g+w "${config.services.cardano-exporter.socketPath}"
    '';
  };

  services.cardano-explorer.enable = true;
  services.cardano-explorer-webapi.enable = true;
  networking.firewall.allowedTCPPorts = [ 80 443 ];

  services.nginx = {
    enable = true;
    recommendedGzipSettings = true;
    recommendedOptimisation = true;
    recommendedProxySettings = true;
    virtualHosts = {
      "explorer.${globals.domain}" = {
        enableACME = true;
        forceSSL = true;
        locations = {
          "/" = {
            root = explorerFrontend;
          };
          #"/socket.io/" = {
          #   proxyPass = "http://127.0.0.1:8110";
          #   extraConfig = ''
          #     proxy_http_version 1.1;
          #     proxy_set_header Upgrade $http_upgrade;
          #     proxy_set_header Connection "upgrade";
          #     proxy_read_timeout 86400;
          #   '';
          #};
          "/api" = {
            proxyPass = "http://127.0.0.1:8100/api";
          };
        };
        #locations."/graphiql" = {
        #  proxyPass = "http://127.0.0.1:3100/graphiql";
        #};
        locations."/graphql" = {
          proxyPass = "http://127.0.0.1:3100/graphql";
        };
      };
      "explorer-ip" = {
        locations = {
          "/metrics2/exporter" = {
            proxyPass = "http://127.0.0.1:8080/";
          };
        };
      };
    };
  };
}
