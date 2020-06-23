#include <string>
#include <memory>

#include "http_filter.h"

#include "json_utils.h"
#include "envoy/registry/registry.h"

#include "http-filter-modsecurity/http_filter.pb.h"
#include "http-filter-modsecurity/http_filter.pb.validate.h"

namespace Envoy {
namespace Server {
namespace Configuration {

class HttpModSecurityFilterConfig : public NamedHttpFilterConfigFactory {
public:

  Http::FilterFactoryCb createFilterFactoryFromProto(const Protobuf::Message& proto_config,
                                                     const std::string&,
                                                     FactoryContext& context) override {

    return createFilter(
        Envoy::MessageUtil::downcastAndValidate<const envoy::config::filter::http::modsecurity::ModsecurityFilterConfigDecoder&>(proto_config, context.messageValidationVisitor()), context);
  }

  /**
   *  Return the Protobuf Message that represents your config incase you have config proto
   */
  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return ProtobufTypes::MessagePtr{new envoy::config::filter::http::modsecurity::ModsecurityFilterConfigDecoder()};
  }

  std::string name() const override { 
    return Envoy::Http::ModSecurityFilterNames::get().ModSecurity;
  }

private:
  Http::FilterFactoryCb createFilter(const envoy::config::filter::http::modsecurity::ModsecurityFilterConfigDecoder& proto_config, FactoryContext& context) {
    Http::HttpModSecurityFilterConfigSharedPtr config =
        std::make_shared<Http::HttpModSecurityFilterConfig>(proto_config, context);

    return [config, &context](Http::FilterChainFactoryCallbacks& callbacks) -> void {
      callbacks.addStreamFilter(
        std::make_shared<Http::HttpModSecurityFilter>(config)
      );
    };
  }

  void translateHttpModSecurityFilter(const Json::Object& json_config,
                                        envoy::config::filter::http::modsecurity::ModsecurityFilterConfigDecoder& proto_config) {
    // normally we want to validate the json_config againts a defined json-schema here.
    JSON_UTIL_SET_STRING(json_config, proto_config, rules_path);
    JSON_UTIL_SET_STRING(json_config, proto_config, rules_inline);
  }
};

/**
 * Static registration for this sample filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<HttpModSecurityFilterConfig, NamedHttpFilterConfigFactory>
    register_;

} // namespace Configuration
} // namespace Server
} // namespace Envoy
