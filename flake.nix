{
  inputs = {
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    naersk = {
      url = "github:nmattia/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixpkgs.url = "nixpkgs/nixos-unstable";
  };

  outputs = { self, fenix, flake-utils, naersk, nixpkgs }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = nixpkgs.legacyPackages."${system}";
          commonNativeBuildInputs = with pkgs; [
            libxml2
            libxslt
            openssl
            pkg-config
            xmlsec
            libtool
          ];
          naersk-lib = (naersk.lib."${system}".override
            {
              inherit (fenix.packages.${system}.minimal) cargo rustc;
            });
        in
        rec {
          # `nix build`
          packages.samael = naersk-lib.buildPackage {
            pname = "samael";
            src = ./.;
            cargoBuildOptions = existingOptions:  existingOptions ++ [ "--features xmlsec" ];
            cargoTestOptions = existingOptions:  existingOptions ++ [ "--features xmlsec" ];
            copyBins = false;
            copyLibs = true;
            doCheck = true;
            doDoc = true;
            nativeBuildInputs = commonNativeBuildInputs;
          };
          defaultPackage = packages.samael;

          # `nix develop`
          devShell = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [
              fenix.packages.${system}.rust-analyzer
              fenix.packages.${system}.stable.toolchain
            ] ++ commonNativeBuildInputs;
          };
        });
}
