{ lib, buildGoModule }:

buildGoModule {
  pname = "mailreportd";
  version = "0.1.0";

  src = ./.;

  vendorHash = "sha256-NdHGLcOOotL4uxXg9FNiYxdWK4d8u13meY6MyTXclX8=";

  ldflags = [
    "-s"
    "-w"
    "-X main.version=0.1.0"
  ];

  meta = with lib; {
    description = "DMARC and SMTP TLS report ingest daemon";
    license = licenses.mit;
    mainProgram = "mailreportd";
  };
}
