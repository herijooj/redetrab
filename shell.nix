{ pkgs ? import <nixpkgs> {} }:

let
  pythonEnv = pkgs.python3.withPackages (ps: with ps; [
    ipython
    pytest
    # Add any other Python packages you might need
  ]);
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    gcc
    valgrind
    glibc
    glibc.dev
    pythonEnv
    python3
  ];

  shellHook = ''
    echo "Entering the Nix development environment for sockets.c"
    echo "GCC version: $(gcc --version | head -n1)"
    echo "Python version: $(python3 --version)"
    echo "Note: Exit nix-shell and use 'sudo' directly to run programs with elevated privileges"
  '';

  NIX_CFLAGS_COMPILE = [
    "-I${pkgs.glibc.dev}/include"
  ];

  NIX_LDFLAGS = [
    "-L${pkgs.glibc}/lib"
  ];
}