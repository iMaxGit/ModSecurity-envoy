#pragma once

#include "common/config/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {

/**
 * Well-known http filter names.
 */
class ModSecurityFilterNameValues {
public:
  const std::string ModSecurity = "envoy.filters.http.modsecurity";
};

using ModSecurityFilterNames = ConstSingleton<ModSecurityFilterNameValues>;

} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy


/**
 * Well-known metadata filter namespaces.
 */

namespace Envoy {
namespace Config {

class ModSecurityMetadataFilterValues {
public:
  const std::string ModSecurity = "envoy.filters.http.modsecurity";
};

using ModSecurityMetadataFilter = ConstSingleton<ModSecurityMetadataFilterValues>;

} // namespace Config
} // namespace Envoy
