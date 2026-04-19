#include "PassRegistry.h"

#include "clang/AST/ASTConsumer.h"
#include "clang/Basic/CodeGenOptions.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"

#include <algorithm>
#include <dlfcn.h>
#include <string>

using namespace clang;

namespace {

int s_bridge_anchor = 0;

std::string getCurrentPluginPath() {
  Dl_info info{};
  if (dladdr(&s_bridge_anchor, &info) == 0 || info.dli_fname == nullptr) {
    return {};
  }
  return info.dli_fname;
}

class NiPassFrontendBridge final : public PluginASTAction {
public:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 llvm::StringRef) override {
    auto plugin_path = getCurrentPluginPath();
    if (plugin_path.empty()) {
      auto &diags = CI.getDiagnostics();
      unsigned diag_id = diags.getCustomDiagID(
          DiagnosticsEngine::Error,
          "NiPass failed to resolve the loaded frontend bridge path");
      diags.Report(diag_id);
      return nullptr;
    }

    auto &pass_plugins = CI.getCodeGenOpts().PassPlugins;
    if (std::find(pass_plugins.begin(), pass_plugins.end(), plugin_path) ==
        pass_plugins.end()) {
      pass_plugins.push_back(std::move(plugin_path));
    }
    return std::make_unique<ASTConsumer>();
  }

  bool ParseArgs(const CompilerInstance &,
                 const std::vector<std::string> &) override {
    return true;
  }

  ActionType getActionType() override { return AddBeforeMainAction; }
};

} // namespace

static FrontendPluginRegistry::Add<NiPassFrontendBridge>
    X("nipass-fplugin-bridge", "Bridge -fplugin to NiPass backend callbacks");
