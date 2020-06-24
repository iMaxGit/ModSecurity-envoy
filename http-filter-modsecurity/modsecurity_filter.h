#pragma once

#include <string>

#include "envoy/server/filter_config.h"
#include "envoy/thread_local/thread_local.h"

#include "common/common/logger.h"
#include "well_known_names.h"
#include "webhook_fetcher.h"

#include "http-filter-modsecurity/modsecurity_filter.pb.h"

#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"

namespace Envoy {
namespace Http {

class ModSecurityFilterConfig : public Logger::Loggable<Logger::Id::filter>,
                                public WebhookFetcherCallback {
public:
  ModSecurityFilterConfig(const http::filter::modsecurity::FilterConfig& proto_config,
                          Server::Configuration::FactoryContext&);
  ~ModSecurityFilterConfig();

  const std::string& rules_path() const { return rules_path_; }
  const std::string& rules_inline() const { return rules_inline_; }
  const http::filter::modsecurity::Webhook& webhook() const { return webhook_; }

  WebhookFetcherSharedPtr webhook_fetcher();

  std::shared_ptr<modsecurity::ModSecurity> modsec_;
  std::shared_ptr<modsecurity::RulesSet> modsec_rules_;

  // Webhook Callbacks
  void onSuccess(const Http::ResponseMessagePtr& response) override;
  void onFailure(FailureReason reason) override;

private:

  struct ThreadLocalWebhook : public ThreadLocal::ThreadLocalObject {
    ThreadLocalWebhook(WebhookFetcher* webhook_fetcher) : webhook_fetcher_(webhook_fetcher) {}
    WebhookFetcherSharedPtr webhook_fetcher_;
  };

  const std::string rules_path_;
  const std::string rules_inline_;
  const http::filter::modsecurity::Webhook webhook_;
  ThreadLocal::SlotPtr tls_;
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
class ModSecurityFilter : public StreamFilter,
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
  FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap&, bool end_stream) override;
  FilterDataStatus decodeData(Buffer::Instance&, bool end_stream) override;
  FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap&) override;
  void setDecoderFilterCallbacks(StreamDecoderFilterCallbacks&) override;

  // Http::StreamEncoderFilter
  FilterHeadersStatus encode100ContinueHeaders(Http::ResponseHeaderMap& headers) override;
  FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap&, bool end_stream) override;
  FilterDataStatus encodeData(Buffer::Instance&, bool end_stream) override;
  FilterTrailersStatus encodeTrailers(Http::ResponseTrailerMap&) override;
  void setEncoderFilterCallbacks(StreamEncoderFilterCallbacks&) override;
  FilterMetadataStatus encodeMetadata(MetadataMap& metadata_map) override;

private:
  const ModSecurityFilterConfigSharedPtr config_;
  StreamDecoderFilterCallbacks* decoder_callbacks_;
  StreamEncoderFilterCallbacks* encoder_callbacks_;
  std::shared_ptr<modsecurity::Transaction> modsec_transaction_;
  
  void logCb(const modsecurity::RuleMessage * ruleMessage);
  /**
   * @return true if intervention of current transaction is disruptive, false otherwise
   */
  bool intervention();

  FilterHeadersStatus getRequestHeadersStatus();
  FilterDataStatus getRequestStatus();

  FilterHeadersStatus getResponseHeadersStatus();
  FilterDataStatus getResponseStatus();

  struct ModSecurityStatus {
    ModSecurityStatus() : intervined(0), request_processed(0), response_processed(0) {}
    bool intervined;
    bool request_processed;
    bool response_processed;
  };

  ModSecurityStatus status_;
};


} // namespace Http
} // namespace Envoy
