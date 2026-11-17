cask "due-diligence-agents" do
  version "1.22.2"
  sha256 "c70e12d605f6004bccfa636409bf98bd1faeb2dc9f9812ce9895b9b96029dfdb"

  url "https://github.com/zoharbabin/due-diligence-agents/releases/download/v#{version}/due-diligence-agents_#{version}_aarch64.dmg"
  name "Due Diligence Agents"
  desc "Forensic M&A due diligence on your own machine"
  homepage "https://github.com/zoharbabin/due-diligence-agents"

  livecheck do
    url :url
    strategy :github_latest
  end

  auto_updates true
  depends_on arch: :arm64
  depends_on :macos

  app "Due Diligence Agents.app"

  zap trash: [
    "~/.dd-projects",
    "~/Library/Application Support/com.zoharbabin.due-diligence-agents",
    "~/Library/Logs/com.zoharbabin.due-diligence-agents",
  ]
end
