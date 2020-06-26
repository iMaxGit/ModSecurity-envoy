#pragma once

#include "modsecurity_filter.h"

#include "http-filter-modsecurity/modsecurity_filter.pb.h"
#include "http-filter-modsecurity/modsecurity_filter.pb.validate.h"

#include "extensions/filters/http/common/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurity {

class ModSecurityFilterFactory
    : public Common::FactoryBase<envoy::extensions::filters::http::modsecurity::v1::ModSecurity> {
public:
  ModSecurityFilterFactory() : FactoryBase(MODSEC_FILTER_NAME) {}

private:
  Http::FilterFactoryCb
  createFilterFactoryFromProtoTyped(const envoy::extensions::filters::http::modsecurity::v1::ModSecurity& config,
                                    const std::string& stats_prefix,
                                    Server::Configuration::FactoryContext& context) override;
};

DECLARE_FACTORY(ModSecurityFilterFactory);

} // namespace ModSecurity
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
