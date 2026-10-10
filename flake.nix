{
  description = "Pinned Node (via mise), JDK 21, and Ghidra 12.1.4 for REA development and real-provider verification";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "x86_64-linux" "aarch64-linux" ];
      forSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          # The release REA verifies (src/ghidra/GhidraInstallationPolicy.ts).
          version = "12.1.4";
          platform = {
            aarch64-darwin = "mac_arm_64";
            x86_64-darwin = "mac_x86_64";
            x86_64-linux = "linux_x86_64";
            aarch64-linux = "linux_arm_64";
          }.${system};
        in {
          # The official release zip, with native tools (decompile, sleigh,
          # demanglers) rebuilt for this host by Ghidra's own offline
          # buildNatives task. The zip ships only linux_x86_64 and win_x86_64.
          ghidra = pkgs.stdenv.mkDerivation {
            pname = "ghidra";
            inherit version;
            src = pkgs.fetchurl {
              url = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${version}_build/ghidra_${version}_PUBLIC_20260921.zip";
              # SHA-256 published in the release notes.
              sha256 = "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db";
            };
            nativeBuildInputs = [ pkgs.unzip pkgs.gradle pkgs.zulu21 ]
              ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.autoPatchelfHook ];
            buildInputs = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.stdenv.cc.cc.lib ];
            dontConfigure = true;
            buildPhase = ''
              runHook preBuild
              export HOME=$TMPDIR GRADLE_USER_HOME=$TMPDIR/gradle JAVA_HOME=${pkgs.zulu21}
              (cd support/gradle && gradle --offline --no-daemon buildNatives)
              runHook postBuild
            '';
            installPhase = ''
              runHook preInstall
              for module in Ghidra/Features/*; do
                if [ -d "$module/build/os/${platform}" ]; then
                  rm -rf "$module/os/${platform}"
                  mkdir -p "$module/os"
                  cp -R "$module/build/os/${platform}" "$module/os/${platform}"
                  rm -rf "$module/build"
                fi
              done
              mkdir -p $out/lib $out/bin
              cp -R . $out/lib/ghidra
              ln -s $out/lib/ghidra/support/analyzeHeadless $out/bin/analyzeHeadless
              runHook postInstall
            '';
            meta = {
              description = "Ghidra ${version} release with host-built native tools";
              homepage = "https://github.com/NationalSecurityAgency/ghidra";
              license = pkgs.lib.licenses.asl20;
              platforms = systems;
            };
          };
        });

      devShells = forSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          ghidra = self.packages.${system}.ghidra;
        in {
          # No Nix C compiler in the shell: real-provider fixtures must build
          # with the host toolchain that matches the host SDK.
          default = pkgs.mkShellNoCC {
            packages = [ pkgs.mise pkgs.zulu21 ghidra pkgs.git ];
            GHIDRA_INSTALL_DIR = "${ghidra}/lib/ghidra";
            JAVA_HOME = "${pkgs.zulu21}";
            shellHook = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isDarwin ''
              # A Nix profile cc/ld cannot link against newer macOS SDK stubs.
              export CC=/usr/bin/clang CXX=/usr/bin/clang++
              export REA_CC=/usr/bin/cc REA_CLANG=/usr/bin/clang
            '' + ''
              # mise provides the pinned Node and npm (mise.toml / .nvmrc).
              eval "$(mise activate --shims bash 2>/dev/null || true)"
            '';
          };
        });
    };
}
