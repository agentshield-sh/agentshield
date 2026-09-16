# Homebrew formula for AgentShield.
#
# This file is the source of truth. On release, CI substitutes VERSION and the
# four SHA256 placeholders from dist/release/SHA256SUMS and pushes the result to
# the tap repository (agentshield-sh/homebrew-tap) as Formula/agentshield.rb.
#
#   brew install agentshield-sh/tap/agentshield
#
# Homebrew verifies each sha256 before installing, which is why this is the
# install path we recommend over a piped shell script.
class Agentshield < Formula
  desc "Security audit for your AI agents and the machine they run on"
  homepage "https://github.com/agentshield-sh/agentshield"
  version "VERSION"
  license "AGPL-3.0-or-later"

  on_macos do
    on_arm do
      url "https://github.com/agentshield-sh/agentshield/releases/download/vVERSION/agentshield-darwin-arm64"
      sha256 "SHA256_DARWIN_ARM64"
    end
    on_intel do
      url "https://github.com/agentshield-sh/agentshield/releases/download/vVERSION/agentshield-darwin-x64"
      sha256 "SHA256_DARWIN_X64"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/agentshield-sh/agentshield/releases/download/vVERSION/agentshield-linux-arm64"
      sha256 "SHA256_LINUX_ARM64"
    end
    on_intel do
      url "https://github.com/agentshield-sh/agentshield/releases/download/vVERSION/agentshield-linux-x64"
      sha256 "SHA256_LINUX_X64"
    end
  end

  def install
    bin.install Dir["agentshield-*"].first => "agentshield"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/agentshield --version")
  end
end
