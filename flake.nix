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
          stdenv = pkgs.stdenv;
          commonNativeBuildInputs = with pkgs; [
            libiconv
            libtool
            libxml2
            libxslt
            llvmPackages.libclang
            openssl
            pkg-config
            xmlsec
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
            # Need to tell bindgen where to find libclang 
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

            # Set C flags for Rust's bindgen program. Unlike ordinary C
            # compilation, bindgen does not invoke $CC directly. Instead it
            # uses LLVM's libclang. To make sure all necessary flags are
            # included we need to look in a few places.
            # See https://web.archive.org/web/20220523141208/https://hoverbear.org/blog/rust-bindgen-in-nix/
            BINDGEN_EXTRA_CLANG_ARGS = "${builtins.readFile "${stdenv.cc}/nix-support/libc-crt1-cflags"} \
                ${builtins.readFile "${stdenv.cc}/nix-support/libc-cflags"} \
                ${builtins.readFile "${stdenv.cc}/nix-support/cc-cflags"} \
                ${builtins.readFile "${stdenv.cc}/nix-support/libcxx-cxxflags"} \
                -idirafter ${pkgs.libiconv}/include \
                -idirafter ${stdenv.cc.cc}/lib/clang/${lib.getVersion stdenv.cc.cc}/include \
            ";

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
            # Need to tell bindgen where to find libclang 
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

            # Set C flags for Rust's bindgen program. Unlike ordinary C
            # compilation, bindgen does not invoke $CC directly. Instead it
            # uses LLVM's libclang. To make sure all necessary flags are
            # included we need to look in a few places.
            # See https://web.archive.org/web/20220523141208/https://hoverbear.org/blog/rust-bindgen-in-nix/
            BINDGEN_EXTRA_CLANG_ARGS = "${builtins.readFile "${stdenv.cc}/nix-support/libc-crt1-cflags"} \
                ${builtins.readFile "${stdenv.cc}/nix-support/libc-cflags"} \
                ${builtins.readFile "${stdenv.cc}/nix-support/cc-cflags"} \
                ${builtins.readFile "${stdenv.cc}/nix-support/libcxx-cxxflags"} \
                -idirafter ${pkgs.libiconv}/include \
                -idirafter ${stdenv.cc.cc}/lib/clang/${lib.getVersion stdenv.cc.cc}/include \
            ";

            nativeBuildInputs = with pkgs; [
              rustPackages.rust-analyzer
              rustPackages.stable.toolchain
            ] ++ commonNativeBuildInputs;
          };
        });
}
