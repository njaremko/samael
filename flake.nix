{
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    nix-filter.url = "github:numtide/nix-filter";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
    crane = {
      url = "github:ipetkov/crane";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
  };

  outputs = { self, nixpkgs, nix-filter, rust-overlay, crane, flake-utils }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          overlays = [
            (import rust-overlay)
            (final: prev: {
              nix-filter = nix-filter.lib;
              rust-toolchain = pkgs.rust-bin.stable.latest.default;
              rust-dev-toolchain = pkgs.rust-toolchain.override {
                extensions = [ "rust-src" ];
              };
            })
          ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
          craneLib =
            (crane.mkLib pkgs).overrideToolchain pkgs.rust-toolchain;
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
        in
        rec {
          # `nix build`
          packages.default =
            let
              fixtureFilter = path: _type:
                builtins.match ".*test_vectors.*" path != null;
              sourceAndFixtures = path: type:
                (fixtureFilter path type) || (craneLib.filterCargoSources path type);
            in
            craneLib.buildPackage {
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
                ${lib.optionalString stdenv.cc.isClang "-idirafter ${stdenv.cc.cc}/lib/clang/${lib.getVersion stdenv.cc.cc}/include"} \
                ${lib.optionalString stdenv.cc.isGNU "-isystem ${stdenv.cc.cc}/include/c++/${lib.getVersion stdenv.cc.cc} -isystem ${stdenv.cc.cc}/include/c++/${lib.getVersion stdenv.cc.cc}/${stdenv.hostPlatform.config} -idirafter ${stdenv.cc.cc}/lib/gcc/${stdenv.hostPlatform.config}/${lib.getVersion stdenv.cc.cc}/include"} \
            ";

              name = "samael";
              src = lib.cleanSourceWith {
                src = ./.;
                filter = sourceAndFixtures;
              };
              nativeBuildInputs = commonNativeBuildInputs;
              cargoExtraArgs = "--features xmlsec";
              cargoTestExtraArgs = "--features xmlsec";
              # cargoTestOptions = existingOptions: existingOptions ++ [ "--features xmlsec" ];
              # copyBins = false;
              # copyLibs = false;
              # copyTarget = true;
              # doCheck = true;
              # doDoc = true;

            };

          # `nix develop`
          devShells.default = pkgs.mkShell {
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
                ${lib.optionalString stdenv.cc.isClang "-idirafter ${stdenv.cc.cc}/lib/clang/${lib.getVersion stdenv.cc.cc}/include"} \
                ${lib.optionalString stdenv.cc.isGNU "-isystem ${stdenv.cc.cc}/include/c++/${lib.getVersion stdenv.cc.cc} -isystem ${stdenv.cc.cc}/include/c++/${lib.getVersion stdenv.cc.cc}/${stdenv.hostPlatform.config} -idirafter ${stdenv.cc.cc}/lib/gcc/${stdenv.hostPlatform.config}/${lib.getVersion stdenv.cc.cc}/include"} \
            ";

            buildInputs = with pkgs; [ rust-dev-toolchain ];
            nativeBuildInputs = commonNativeBuildInputs;
            shellHook = ''
              export DIRENV_LOG_FORMAT=""
            '';
          };
        });
}
