{ pkgs, lib, ... }:

let
  inherit (pkgs) stdenv;
  samaelEnv = import ./nix/samael-env.nix { inherit pkgs lib; };
  check = name: "nix build --accept-flake-config .#checks.${stdenv.system}.${name} -L";
in
{
  languages.rust = {
    enable = true;
    channel = "nightly";
    lsp.enable = false;
    components = [
      "rustc"
      "cargo"
      "clippy"
      "rustfmt"
      "rust-src"
    ];
  };
  languages.c.enable = false;

  packages = samaelEnv.nativeBuildInputs ++ (with pkgs; [
    cargo-audit
    cargo-nextest
    nix
    nixpkgs-fmt
  ]);

  env = samaelEnv.env;

  scripts = {
    "samael-build" = {
      description = "Build the default Nix package.";
      exec = "nix build --accept-flake-config -L";
    };

    "samael-test" = {
      description = "Run the xmlsec nextest check.";
      exec = check "samael-nextest";
    };

    "samael-clippy" = {
      description = "Run the clippy check.";
      exec = check "samael-clippy";
    };

    "samael-doc" = {
      description = "Build crate documentation.";
      exec = check "samael-doc";
    };

    "samael-fmt" = {
      description = "Check formatting.";
      exec = check "samael-fmt";
    };

    "samael-audit" = {
      description = "Audit dependencies.";
      exec = check "samael-audit";
    };
  };

  enterTest = ''
    samael-test
  '';
}
