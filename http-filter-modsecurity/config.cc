#include <string>
#include <memory>

#include "config.h"

#include "envoy/registry/registry.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurity {

Http::FilterFactoryCb ModSecurityFilterFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::modsecurity::v1::ModSecurity& proto_config,
    const std::string& stats_prefix,
    Server::Configuration::FactoryContext& context) {

  ModSecurityFilterConfigSharedPtr config = std::make_shared<ModSecurityFilterConfig>(
      proto_config, stats_prefix, context);

  return [config, &context](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamFilter(std::make_shared<ModSecurityFilter>(config));
  };
}

Router::RouteSpecificFilterConfigConstSharedPtr
RoleBasedAccessControlFilterConfigFactory::createRouteSpecificFilterConfigTyped(
    envoy::extensions::filters::http::modsecurity::v1::PerRouteConfig& proto_config,
    Server::Configuration::ServerFactoryContext&, ProtobufMessage::ValidationVisitor&) {
  return std::make_shared<const ModSecurityRouteSpecificFilterConfig>(proto_config);
}

REGISTER_FACTORY(ModSecurityFilterFactory,
                 Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace ModSecurity
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
