#pragma once

#include "modsecurity_filter.h"

#include "http-filter-modsecurity/modsecurity_filter.pb.h"
#include "http-filter-modsecurity/modsecurity_filter.pb.validate.h"

// #include "extensions/filters/http/common/factory_base.h" // v1.18
#include "source/extensions/filters/http/common/factory_base.h" // v1.20

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurity {

class ModSecurityFilterFactory
    : public Common::FactoryBase<envoy::extensions::filters::http::modsecurity::v1::ModSecurity,
                                 envoy::extensions::filters::http::modsecurity::v1::PerRouteConfig> {
public:
  ModSecurityFilterFactory() : FactoryBase(filter_name) {}

private:
  Http::FilterFactoryCb
  createFilterFactoryFromProtoTyped(const envoy::extensions::filters::http::modsecurity::v1::ModSecurity& config,
                                    const std::string& stats_prefix,
                                    Server::Configuration::FactoryContext& context) override;

  Router::RouteSpecificFilterConfigConstSharedPtr createRouteSpecificFilterConfigTyped(
      const envoy::extensions::filters::http::modsecurity::v1::PerRouteConfig& proto_config,
      Server::Configuration::ServerFactoryContext& context,
      ProtobufMessage::ValidationVisitor& validator) override;

};

DECLARE_FACTORY(ModSecurityFilterFactory);

} // namespace ModSecurity
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
