#include <string>
#include <memory>

#include "modsecurity_filter.h"

#include "json_utils.h"
#include "envoy/registry/registry.h"

#include "http-filter-modsecurity/modsecurity_filter.pb.h"
#include "http-filter-modsecurity/modsecurity_filter.pb.validate.h"

namespace Envoy {
namespace Server {
namespace Configuration {

class ModSecurityFilterConfigFactory : public NamedHttpFilterConfigFactory {
public:

  Http::FilterFactoryCb createFilterFactoryFromProto(const Protobuf::Message& proto_config,
                                                     const std::string&,
                                                     FactoryContext& context) override {

    return createFilter(
        Envoy::MessageUtil::downcastAndValidate<const http::filter::modsecurity::FilterConfig&>(proto_config, context.messageValidationVisitor()), context);
  }

  /**
   *  Return the Protobuf Message that represents your config incase you have config proto
   */
  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return ProtobufTypes::MessagePtr{new http::filter::modsecurity::FilterConfig()};
  }

  std::string name() const override {
    return MOD_SECURITY_FILTER_NAME;
  }

private:
  Http::FilterFactoryCb createFilter(const http::filter::modsecurity::FilterConfig& proto_config, FactoryContext& context) {
    Http::ModSecurityFilterConfigSharedPtr config =
        std::make_shared<Http::ModSecurityFilterConfig>(proto_config, context);

    return [config, &context](Http::FilterChainFactoryCallbacks& callbacks) -> void {
      auto filter = new Http::ModSecurityFilter(config)
      callbacks.addStreamFilter(Http::StreamFilterSharedPtr{filter});
    };
  }

  void translateModSecurityFilter(const Json::Object& json_config,
                                  http::filter::modsecurity::FilterConfig& proto_config) {
    // normally we want to validate the json_config againts a defined json-schema here.
    JSON_UTIL_SET_STRING(json_config, proto_config, rules_path);
    JSON_UTIL_SET_STRING(json_config, proto_config, rules_inline);
  }
};

/**
 * Static registration for this sample filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<ModSecurityFilterConfigFactory, NamedHttpFilterConfigFactory>
    register_;

} // namespace Configuration
} // namespace Server
} // namespace Envoy
