cask "due-diligence-agents" do
  version "1.22.0"
  sha256 "b82790ae9b1e055889864c137fc37eba7b61bc6390307504cf26e9326e48bbe6"

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
