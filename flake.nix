{
    inputs.nixpkgs.url = "github:NixOS/nixpkgs";
    outputs = { self, nixpkgs }: let
        pkgs = import nixpkgs {
            system = "x86_64-linux";
        };
    in {
        packages.x86_64-linux.default = pkgs.stdenv.mkDerivation {
            name = "random-src";
            src = ./.;
            buildInputs = with pkgs; [ libnetfilter_conntrack libnetfilter_queue ];
            nativeBuildInputs = with pkgs; [ cmake ];
        };
    };
}
