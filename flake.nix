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
          rustPackages = fenix.packages.${system};
          naersk-lib = (naersk.lib."${system}".override
            {
              inherit (rustPackages.minimal) cargo rustc;
            });
        in
        rec {
          # `nix build`
          packages.samael = naersk-lib.buildPackage {
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            pname = "samael";
            src = ./.;
            cargoBuildOptions = existingOptions:  existingOptions ++ [ "--features xmlsec" ];
            cargoTestOptions = existingOptions:  existingOptions ++ [ "--features xmlsec" ];
            copyBins = false;
            copyLibs = false;
            copyTarget = true;
            doCheck = true;
            doDoc = true;
            nativeBuildInputs = commonNativeBuildInputs;
          };
          defaultPackage = packages.samael;

          # `nix develop`
          devShell = pkgs.mkShell {
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            nativeBuildInputs = with pkgs; [
              rustPackages.rust-analyzer
              rustPackages.stable.toolchain
            ] ++ commonNativeBuildInputs;
          };
        });
}
