{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    nix-filter.url = "github:numtide/nix-filter";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
    crane = {
      url = "github:ipetkov/crane";
    };
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
    devenv = {
      url = "github:cachix/devenv";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rust-overlay.follows = "rust-overlay";
    };
  };

  nixConfig = {
    extra-trusted-public-keys = [ "devenv.cachix.org-1:w1cLUi8dv3hnoSPGAuibQv+f9TZLr6cv/Hm9XgU50cw=" ];
    extra-substituters = [ "https://devenv.cachix.org" ];
  };

  outputs = { self, nixpkgs, nix-filter, rust-overlay, crane, advisory-db, flake-utils, devenv } @ inputs:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          overlays = [
            (import rust-overlay)
            (final: prev: {
              nix-filter = nix-filter.lib;
              rust-toolchain = final.rust-bin.nightly.latest.default;
            })
          ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
          craneLib =
            (crane.mkLib pkgs).overrideToolchain pkgs.rust-toolchain;
          lib = pkgs.lib;
          samaelEnv = import ./nix/samael-env.nix { inherit pkgs lib; };
          fixtureFilter = path: _type:
            builtins.match ".*test_vectors.*" path != null ||
            builtins.match ".*\.h" path != null;
          sourceAndFixtures = path: type:
            (fixtureFilter path type) || (craneLib.filterCargoSources path type);
          src = lib.cleanSourceWith {
            src = ./.;
            filter = sourceAndFixtures;
          };
          cargoFile = builtins.fromTOML (builtins.readFile ./Cargo.toml);
          commonArgs = samaelEnv.env // {
            pname = "samael";
            inherit src;
            version = cargoFile.package.version;

            nativeBuildInputs = samaelEnv.nativeBuildInputs;
            cargoExtraArgs = "--features xmlsec";
            cargoTestExtraArgs = "--features xmlsec";
          };
          # Build *just* the cargo dependencies, so we can reuse
          # all of that work (e.g. via cachix) when running in CI
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
          samael = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
          });
        in
        rec {
          # `nix build`
          packages.default = samael;

          devShells.default = devenv.lib.mkShell {
            inherit inputs pkgs;
            modules = [ ./devenv.nix ];
          };

          checks = {
            # Build the crate as part of `nix flake check` for convenience
            inherit samael;

            # Run clippy (and deny all warnings) on the crate source,
            # again, resuing the dependency artifacts from above.
            #
            # Note that this is done as a separate derivation so that
            # we can block the CI if there are issues here, but not
            # prevent downstream consumers from building our crate by itself.
            samael-clippy = craneLib.cargoClippy (commonArgs // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets"; #--  --deny warnings
            });

            samael-doc = craneLib.cargoDoc (commonArgs // {
              inherit cargoArtifacts;
            });

            # Check formatting
            samael-fmt = craneLib.cargoFmt {
              inherit src;
            };

            # Audit dependencies
            samael-audit = craneLib.cargoAudit {
              inherit src advisory-db;
            };

            # Run tests with cargo-nextest
            # Consider setting `doCheck = false` on `samael` if you do not want
            # the tests to run twice
            samael-nextest = craneLib.cargoNextest (commonArgs // {
              inherit cargoArtifacts;
              cargoExtraArgs = "";
              cargoNextestExtraArgs = "--features xmlsec";
              partitions = 1;
              partitionType = "count";
            });
          };
        });
}
