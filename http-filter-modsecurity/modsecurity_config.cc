#include <string>
#include <memory>

#include "modsecurity_filter.h"

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
      Envoy::MessageUtil::downcastAndValidate<const modsecurity::filter::Config&>(proto_config, context.messageValidationVisitor()),
      context);
  }

  /**
   *  Return the Protobuf Message that represents your config incase you have config proto
   */
  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return ProtobufTypes::MessagePtr{new modsecurity::filter::Config()};
  }

  std::string name() const override {
    return MOD_SECURITY_FILTER_NAME;
  }

private:
  Http::FilterFactoryCb createFilter(const modsecurity::filter::Config& proto_config, FactoryContext& context) {
    Http::ModSecurityFilterConfigSharedPtr config =
        std::make_shared<Http::ModSecurityFilterConfig>(proto_config, context);

    return [config, &context](Http::FilterChainFactoryCallbacks& callbacks) -> void {
      auto filter = new Http::ModSecurityFilter(config);
      callbacks.addStreamFilter(Http::StreamFilterSharedPtr{filter});
    };
  }
};

REGISTER_FACTORY(ModSecurityFilterConfigFactory, NamedHttpFilterConfigFactory);

} // namespace Configuration
} // namespace Server
} // namespace Envoy
