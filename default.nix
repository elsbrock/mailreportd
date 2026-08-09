{ lib, buildGoModule }:

buildGoModule {
  pname = "mailreportd";
  version = "0.1.0";

  src = ./.;

  vendorHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

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
