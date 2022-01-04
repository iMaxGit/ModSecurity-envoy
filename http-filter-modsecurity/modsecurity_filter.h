#pragma once

#include <string>

/* v 1.18
#include "common/common/logger.h"
#include "common/http/header_map_impl.h"
*/

/* v1.20 */
#include "source/common/common/logger.h"
#include "source/common/http/header_map_impl.h"

#include "envoy/thread_local/thread_local.h"
#include "envoy/http/filter.h"
#include "envoy/http/header_map.h"
#include "envoy/runtime/runtime.h"

#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "envoy/server/filter_config.h"

/* v1.18
#include "common/buffer/buffer_impl.h"
#include "common/protobuf/protobuf.h"
*/

/* v1.20 */
#include "source/common/buffer/buffer_impl.h"
#include "source/common/protobuf/protobuf.h"

#include "webhook_fetcher.h"

#include "http-filter-modsecurity/modsecurity_filter.pb.h"

#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurity {


constexpr char filter_name[] = "envoy.filters.http.modsecurity";


#define ALL_MODSEC_STATS(COUNTER)             \
  COUNTER(request_processed)                  \
  COUNTER(response_processed)


struct ModSecurityStats {
  ALL_MODSEC_STATS(GENERATE_COUNTER_STRUCT)
};


class ModSecurityRouteSpecificFilterConfig : public Router::RouteSpecificFilterConfig {
public:
  ModSecurityRouteSpecificFilterConfig(const envoy::extensions::filters::http::modsecurity::v1::PerRouteConfig&);

  bool disable_request() const { return disable_request_; }
  bool disable_response() const { return disable_response_; }

private:
  const bool disable_request_;
  const bool disable_response_;
};


class ModSecurityFilterConfig : public Logger::Loggable<Logger::Id::filter>,
                                public WebhookFetcherCallback {
public:
  ModSecurityFilterConfig(const envoy::extensions::filters::http::modsecurity::v1::ModSecurity& proto_config,
                          const std::string& stats_prefix,
                          Server::Configuration::FactoryContext&);
  ~ModSecurityFilterConfig();

  Runtime::Loader& runtime() { return runtime_; }
  ModSecurityStats& stats() { return stats_; }

  // get config
  const std::string& rules_path() const { return rules_path_; }
  const std::string& rules_inline() const { return rules_inline_; }
  const envoy::extensions::filters::http::modsecurity::v1::ModSecurity::Webhook& webhook() const { return webhook_; }

  std::shared_ptr<modsecurity::ModSecurity> modsec() const { return modsec_; }
  std::shared_ptr<modsecurity::RulesSet> modsec_rules() const { return modsec_rules_; }

  void invoke_webhook(const modsecurity::RuleMessage*);

  // Webhook Callbacks
  void onSuccess(const Http::ResponseMessagePtr& response) override;
  void onFailure(FailureReason reason) override;

private:
  static ModSecurityStats generateStats(const std::string& prefix, Stats::Scope& scope) {
    return ModSecurityStats{ALL_MODSEC_STATS(POOL_COUNTER_PREFIX(scope, prefix))};
  }

  struct ThreadLocalWebhook : public ThreadLocal::ThreadLocalObject {
    ThreadLocalWebhook(WebhookFetcher* webhook_fetcher) : webhook_fetcher_(webhook_fetcher) {}
    WebhookFetcherSharedPtr webhook_fetcher_;
  };

  // config data
  const std::string rules_path_;
  const std::string rules_inline_;
  const envoy::extensions::filters::http::modsecurity::v1::ModSecurity::Webhook webhook_;
  ThreadLocal::SlotPtr tls_;

  ModSecurityStats stats_;
  Runtime::Loader& runtime_;

  // share modsecurity obj
  std::shared_ptr<modsecurity::ModSecurity> modsec_;
  std::shared_ptr<modsecurity::RulesSet> modsec_rules_;
};

typedef std::shared_ptr<ModSecurityFilterConfig> ModSecurityFilterConfigSharedPtr;

/**
 * Transaction flow:
 * 1. Disruptive?
 *   a. StopIterationAndBuffer until finished processing request
 *      a1. Should block? sendLocalReply
 *           decode should return StopIteration to avoid sending data to upstream.
 *           encode should return Continue to let local reply flow back to downstream.
 *      a2. Request is valid
 *           decode should return Continue to let request flow upstream.
 *           encode should return StopIterationAndBuffer until finished processing response
 *               a2a. Should block? goto a1.
 *               a2b. Response is valid, return Continue
 * 
 * 2. Non-disruptive - always return Continue
 *   
 */
class ModSecurityFilter : public Http::StreamFilter,
                          public Logger::Loggable<Logger::Id::filter> {
public:
  /**
   * This static function will be called by modsecurity and internally invoke logCb filter's method
   */
  static void _logCb(void* data, const void* ruleMessagev);

    ModSecurityFilter(ModSecurityFilterConfigSharedPtr);
  ~ModSecurityFilter();

  // Http::StreamFilterBase
  void onDestroy() override;

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap&, bool end_stream) override;
  Http::FilterDataStatus decodeData(Buffer::Instance&, bool end_stream) override;
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap&) override;
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks&) override;

  // Http::StreamEncoderFilter
  Http::FilterHeadersStatus encode100ContinueHeaders(Http::ResponseHeaderMap& headers) override;
  Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap&, bool end_stream) override;
  Http::FilterDataStatus encodeData(Buffer::Instance&, bool end_stream) override;
  Http::FilterTrailersStatus encodeTrailers(Http::ResponseTrailerMap&) override;
  void setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks&) override;
  Http::FilterMetadataStatus encodeMetadata(Http::MetadataMap& metadata_map) override;

private:
  const ModSecurityFilterConfigSharedPtr config_;
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_;
  Http::StreamEncoderFilterCallbacks* encoder_callbacks_;
  std::shared_ptr<modsecurity::Transaction> modsec_transaction_;
  
  void logCb(const modsecurity::RuleMessage * ruleMessage);

  bool requestDisabled();
  bool responseDisabled();
  /**
   * @return true if intervention of current transaction is disruptive, false otherwise
   */
  bool intervention();

  Http::FilterHeadersStatus getRequestHeadersStatus();
  Http::FilterDataStatus getRequestStatus();

  Http::FilterHeadersStatus getResponseHeadersStatus();
  Http::FilterDataStatus getResponseStatus();

  struct ModSecurityStatus {
    ModSecurityStatus() : intervined(0), request_processed(0), response_processed(0) {}
    bool intervined;
    bool request_processed;
    bool response_processed;
  };

  ModSecurityStatus status_;
};


} // namespace ModSecurity
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
