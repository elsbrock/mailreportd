{ config, lib, pkgs, ... }:

let
  cfg = config.services.mailreportd;
  format = pkgs.formats.yaml { };
  configFile = format.generate "mailreportd.yaml" cfg.settings;
in
{
  options.services.mailreportd = {
    enable = lib.mkEnableOption "the mailreportd DMARC and SMTP TLS report ingest daemon";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The mailreportd package to run.";
    };

    settings = lib.mkOption {
      inherit (format) type;
      default = { };
      description = ''
        Contents of the mailreportd configuration file.

        Credentials are never written here. Point a feeder's `password_file` at
        a systemd credential instead, which this module places at
        `/run/credentials/mailreportd.service/<name>` for every entry in
        {option}`services.mailreportd.credentials`.
      '';
      example = lib.literalExpression ''
        {
          tenants = [{ id = "default"; domains = [ "example.org" ]; }];
          feeders = [{
            name = "dmarc";
            type = "imap";
            host = "mail.example.org";
            username = "dmarc@example.org";
            password_file = "/run/credentials/mailreportd.service/dmarc-password";
          }];
        }
      '';
    };

    credentials = lib.mkOption {
      type = lib.types.attrsOf lib.types.path;
      default = { };
      description = ''
        Files passed to the unit through systemd's LoadCredential, keyed by the
        name they are exposed under. Each becomes readable at
        `/run/credentials/mailreportd.service/<name>` and nowhere else.
      '';
      example = lib.literalExpression ''
        { dmarc-password = config.sops.secrets."mail/mailreportd/dmarc".path; }
      '';
    };

    stateDir = lib.mkOption {
      type = lib.types.str;
      default = "mailreportd";
      description = ''
        Directory under /var/lib holding the report database. Changing this
        starts from an empty database; the old one is not migrated.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # The database path is owned by the module rather than left to the
    # operator, because it has to agree with StateDirectory for the sandbox to
    # permit writing to it at all.
    services.mailreportd.settings.storage.path =
      lib.mkDefault "/var/lib/${cfg.stateDir}/reports.db";

    systemd.services.mailreportd = {
      description = "DMARC and SMTP TLS report ingest";
      documentation = [ "https://github.com/elsbrock/mailreportd" ];
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      serviceConfig = {
        Type = "exec";
        ExecStart = "${lib.getExe cfg.package} -config ${configFile}";
        # Validates the configuration before the unit is considered started, so
        # a typo fails the deploy rather than looping in Restart.
        ExecStartPre = "${lib.getExe cfg.package} -config ${configFile} -check";
        Restart = "on-failure";
        RestartSec = "10s";

        DynamicUser = true;
        StateDirectory = cfg.stateDir;
        StateDirectoryMode = "0700";

        LoadCredential = lib.mapAttrsToList (name: path: "${name}:${path}") cfg.credentials;

        # Hardening. The daemon needs outbound IMAP, DNS, and its own state
        # directory; nothing else.
        CapabilityBoundingSet = [ "" ];
        AmbientCapabilities = [ "" ];
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        RemoveIPC = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
        UMask = "0077";
      };
    };
  };
}
