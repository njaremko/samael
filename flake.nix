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
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = { self, fenix, flake-utils, naersk, nixpkgs, flake-compat }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs = nixpkgs.legacyPackages."${system}";
          lib = pkgs.lib;
          commonNativeBuildInputs = with pkgs; [
            libxml2
            libxslt
            openssl
            pkg-config
            xmlsec
            libtool
            pkgs.llvmPackages.libclang
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
            pname = "samael";
            src = ./.;
            cargoBuildOptions = existingOptions: existingOptions ++ [ "--features xmlsec" ];
            cargoTestOptions = existingOptions: existingOptions ++ [ "--features xmlsec" ];
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
            BINDGEN_EXTRA_CLANG_ARGS = "-isystem ${pkgs.llvmPackages.libclang.lib}/lib/clang/${lib.getVersion pkgs.clang}/include";

            nativeBuildInputs = with pkgs; [
              rustPackages.rust-analyzer
              rustPackages.stable.toolchain
            ] ++ commonNativeBuildInputs;
          };
        });
}
