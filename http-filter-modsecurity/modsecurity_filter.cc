#include <string>
#include <vector>
#include <iostream>

#include "modsecurity_filter.h"
#include "envoy/server/filter_config.h"

#include "utility.h"

#include "absl/container/fixed_array.h"
#include "envoy/server/filter_config.h"
#include "common/http/utility.h"
#include "common/http/headers.h"
#include "common/config/metadata.h"
#include "common/json/json_loader.h"

#include "modsecurity/rule.h"
#include "modsecurity/rule_message.h"
#include "modsecurity/rules_set.h"
#include "modsecurity/rules_set_properties.h"

namespace Envoy {
namespace Http {

/* 
 *  Filter Config
 */

// constructor
ModSecurityFilterConfig::ModSecurityFilterConfig(const http::filter::modsecurity::FilterConfig& proto_config,
                                                 Server::Configuration::FactoryContext& context)
    : rules_path_(proto_config.rules_path()),
      rules_inline_(proto_config.rules_inline()),
      webhook_(proto_config.webhook()),
      tls_(context.threadLocal().allocateSlot()) {

    modsec_.reset(new modsecurity::ModSecurity());
    modsec_->setConnectorInformation("ModSecurity-envoy v0.1.0 (ModSecurity)");
    modsec_->setServerLogCb(ModSecurityFilter::_logCb,
                            modsecurity::RuleMessageLogProperty | modsecurity::IncludeFullHighlightLogProperty);

    modsec_rules_.reset(new modsecurity::RulesSet());
    if (!rules_path().empty()) {
        int rulesLoaded = modsec_rules_->loadFromUri(rules_path().c_str());
        ENVOY_LOG(debug, "Loading ModSecurity config from {}", rules_path());
        if (rulesLoaded == -1) {
            ENVOY_LOG(error, "Failed to load rules: {}", modsec_rules_->getParserError());
        } else {
            ENVOY_LOG(info, "Loaded {} rules", rulesLoaded);
        };
    }
    if (!rules_inline().empty()) {
        int rulesLoaded = modsec_rules_->load(rules_inline().c_str());
        ENVOY_LOG(debug, "Loading ModSecurity inline rules");
        if (rulesLoaded == -1) {
            ENVOY_LOG(error, "Failed to load rules: {}", modsec_rules_->getParserError());
        } else {
            ENVOY_LOG(info, "Loaded {} inline rules", rulesLoaded);
        };
    }

    tls_->set([this, &context](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
      return std::make_shared<ThreadLocalWebhook>(new WebhookFetcher(context.clusterManager(), 
                webhook_.http_uri(), 
                webhook_.secret(), 
                *this));
    });
}

// destructor
ModSecurityFilterConfig::~ModSecurityFilterConfig() {
}

// webhook
WebhookFetcherSharedPtr ModSecurityFilterConfig::webhook_fetcher() {
    return tls_->getTyped<ThreadLocalWebhook>().webhook_fetcher_;
}

// on success
void ModSecurityFilterConfig::onSuccess(const Http::ResponseMessagePtr&) {
    ENVOY_LOG(info, "webhook success!");
}

// on fail
void ModSecurityFilterConfig::onFailure(FailureReason) {
    ENVOY_LOG(info, "webhook failure!");
}

/* 
 *  Filter
 */

// constructor
ModSecurityFilter::ModSecurityFilter(ModSecurityFilterConfigSharedPtr config)
    : config_(config) {
    
    modsec_transaction_.reset(new modsecurity::Transaction(config_->modsec_.get(), config_->modsec_rules_.get(), this));
}

// destructor
ModSecurityFilter::~ModSecurityFilter() {
}

void ModSecurityFilter::onDestroy() {
    modsec_transaction_->processLogging();
}

const char* getProtocolString(const Protocol protocol) {
    switch (protocol) {
    case Protocol::Http10:
        return "1.0";
    case Protocol::Http11:
        return "1.1";
    case Protocol::Http2:
        return "2.0";
    case Protocol::Http3:
        return "3.0";
    }
    NOT_REACHED_GCOVR_EXCL_LINE;
}

FilterHeadersStatus ModSecurityFilter::decodeHeaders(Http::RequestHeaderMap& headers, bool end_stream) {
    ENVOY_LOG(debug, "ModSecurityFilter::decodeHeaders");
    if (status_.intervined || status_.request_processed) {
        ENVOY_LOG(debug, "Processed");
        return getRequestHeadersStatus();
    }

    const auto& metadata = decoder_callbacks_->streamInfo().dynamicMetadata().filter_metadata();
    const auto filter_it = metadata.find(MOD_SECURITY_FILTER_NAME);
    if (filter_it != metadata.end()) {
        const auto fields = filter_it->second.fields();
        const auto disable_it = fields.find("disable");
        if (disable_it != fields.end() || disable_it->second.bool_value()) {
            ENVOY_LOG(debug, "Filter disabled");
            status_.request_processed = true;
            return FilterHeadersStatus::Continue;
        }
        const auto disable_request_it = fields.find("disable_request");
        if (disable_request_it != fields.end() || disable_request_it->second.bool_value()) {
            ENVOY_LOG(debug, "Filter disabled");
            status_.request_processed = true;
            return FilterHeadersStatus::Continue;
        }
    }

    auto downstreamAddress = decoder_callbacks_->streamInfo().downstreamLocalAddress();
    // TODO - Upstream is (always?) still not resolved in this stage. Use our local proxy's ip. Is this what we want?
    ASSERT(decoder_callbacks_->connection() != nullptr);
    auto localAddress = decoder_callbacks_->connection()->localAddress();
    // According to documentation, downstreamAddress should never be nullptr
    ASSERT(downstreamAddress != nullptr);
    ASSERT(downstreamAddress->type() == Network::Address::Type::Ip);
    ASSERT(localAddress != nullptr);
    ASSERT(localAddress->type() == Network::Address::Type::Ip);
    modsec_transaction_->processConnection(downstreamAddress->ip()->addressAsString().c_str(), 
                                          downstreamAddress->ip()->port(),
                                          localAddress->ip()->addressAsString().c_str(), 
                                          localAddress->ip()->port());
    if (intervention()) {
        return FilterHeadersStatus::StopIteration;
    }

    auto uri = headers.Path();
    auto method = headers.Method();
    modsec_transaction_->processURI(std::string(uri->value().getStringView()).c_str(), 
                                    std::string(method->value().getStringView()).c_str(),
                                    getProtocolString(decoder_callbacks_->streamInfo().protocol().value_or(Protocol::Http11)));
    if (intervention()) {
        return FilterHeadersStatus::StopIteration;
    }
    
    headers.iterate(
            [](const HeaderEntry& header, void* context) -> Http::HeaderMap::Iterate {
                
                std::string k = std::string(header.key().getStringView());
                std::string v = std::string(header.value().getStringView());
                static_cast<ModSecurityFilter*>(context)->modsec_transaction_->addRequestHeader(k.c_str(), v.c_str());
                // TODO - does this special case makes sense? it doesn't exist on apache/nginx modsecurity bridges.
                // host header is cannonized to :authority even on http older than 2 
                // see https://github.com/envoyproxy/envoy/issues/2209
                if (k == Headers::get().Host.get()) {
                    static_cast<ModSecurityFilter*>(context)->modsec_transaction_->addRequestHeader(Headers::get().HostLegacy.get().c_str(), v.c_str());
                }
                return Http::HeaderMap::Iterate::Continue;
            },
            this);
    modsec_transaction_->processRequestHeaders();
    if (end_stream) {
        status_.request_processed = true;
    }
    if (intervention()) {
        return FilterHeadersStatus::StopIteration;
    }
    return getRequestHeadersStatus();
}

FilterDataStatus ModSecurityFilter::decodeData(Buffer::Instance& data, bool end_stream) {
    ENVOY_LOG(debug, "ModSecurityFilter::decodeData");
    if (status_.intervined || status_.request_processed) {
        ENVOY_LOG(debug, "Processed");
        return getRequestStatus();
    }

    for (const Buffer::RawSlice& slice : data.getRawSlices()) {
        size_t requestLen = modsec_transaction_->getRequestBodyLength();
        // If append fails or append reached the limit, test for intervention (in case SecRequestBodyLimitAction is set to Reject)
        // Note, we can't rely solely on the return value of append, when SecRequestBodyLimitAction is set to Reject it returns true and sets the intervention
        if (modsec_transaction_->appendRequestBody(static_cast<unsigned char*>(slice.mem_), slice.len_) == false ||
            (slice.len_ > 0 && requestLen == modsec_transaction_->getRequestBodyLength())) {
            ENVOY_LOG(debug, "ModSecurityFilter::decodeData appendRequestBody reached limit");
            if (intervention()) {
                return FilterDataStatus::StopIterationNoBuffer;
            }
            // Otherwise set to process request
            end_stream = true;
            break;
        }
    }

    if (end_stream) {
        status_.request_processed = true;
        modsec_transaction_->processRequestBody();
    }
    if (intervention()) {
        return FilterDataStatus::StopIterationNoBuffer;
    } 
    return getRequestStatus();
}

FilterTrailersStatus ModSecurityFilter::decodeTrailers(Http::RequestTrailerMap&) {
  return FilterTrailersStatus::Continue;
}

void ModSecurityFilter::setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}


FilterHeadersStatus ModSecurityFilter::encodeHeaders(Http::ResponseHeaderMap& headers, bool) {
    ENVOY_LOG(debug, "ModSecurityFilter::encodeHeaders");
    if (status_.intervined || status_.response_processed) {
        ENVOY_LOG(debug, "Processed");
        return getResponseHeadersStatus();
    }

    const auto& metadata = decoder_callbacks_->streamInfo().dynamicMetadata().filter_metadata();
    const auto filter_it = metadata.find(MOD_SECURITY_FILTER_NAME);
    if (filter_it != metadata.end()) {
        const auto fields = filter_it->second.fields();
        const auto disable_it = fields.find("disable");
        if (disable_it != fields.end() || disable_it->second.bool_value()) {
            ENVOY_LOG(debug, "Filter disabled");
            status_.request_processed = true;
            return FilterHeadersStatus::Continue;
        }
        const auto disable_response_it = fields.find("disable_response");
        if (disable_response_it != fields.end() || disable_response_it->second.bool_value()) {
            ENVOY_LOG(debug, "Filter disabled");
            status_.request_processed = true;
            return FilterHeadersStatus::Continue;
        }
    }

    uint64_t response_code = Http::Utility::getResponseStatus(headers);
    headers.iterate(
            [](const HeaderEntry& header, void* context) -> Http::HeaderMap::Iterate {
                static_cast<ModSecurityFilter*>(context)->modsec_transaction_->addResponseHeader(
                    std::string(header.key().getStringView()).c_str(),
                    std::string(header.value().getStringView()).c_str()
                );
                return Http::HeaderMap::Iterate::Continue;
            },
            this);
    modsec_transaction_->processResponseHeaders(response_code, 
            getProtocolString(encoder_callbacks_->streamInfo().protocol().value_or(Protocol::Http11)));
        
    if (intervention()) {
        return FilterHeadersStatus::StopIteration;
    }
    return getResponseHeadersStatus();
}

FilterHeadersStatus ModSecurityFilter::encode100ContinueHeaders(Http::ResponseHeaderMap&) {
    return FilterHeadersStatus::Continue;
}

FilterDataStatus ModSecurityFilter::encodeData(Buffer::Instance& data, bool end_stream) {
    ENVOY_LOG(debug, "ModSecurityFilter::encodeData");
    if (status_.intervined || status_.response_processed) {
        ENVOY_LOG(debug, "Processed");
        return getResponseStatus();
    }
    
    for (const Buffer::RawSlice& slice : data.getRawSlices()) {
        size_t responseLen = modsec_transaction_->getResponseBodyLength();
        // If append fails or append reached the limit, test for intervention (in case SecResponseBodyLimitAction is set to Reject)
        // Note, we can't rely solely on the return value of append, when SecResponseBodyLimitAction is set to Reject it returns true and sets the intervention
        if (modsec_transaction_->appendResponseBody(static_cast<unsigned char*>(slice.mem_), slice.len_) == false ||
            (slice.len_ > 0 && responseLen == modsec_transaction_->getResponseBodyLength())) {
            ENVOY_LOG(debug, "ModSecurityFilter::encodeData appendResponseBody reached limit");
            if (intervention()) {
                return FilterDataStatus::StopIterationNoBuffer;
            }
            // Otherwise set to process response
            end_stream = true;
            break;
        }
    }

    if (end_stream) {
        status_.response_processed = true;
        modsec_transaction_->processResponseBody();
    }
    if (intervention()) {
        return FilterDataStatus::StopIterationNoBuffer;
    }
    return getResponseStatus();
}

FilterTrailersStatus ModSecurityFilter::encodeTrailers(Http::ResponseTrailerMap&) {
    return FilterTrailersStatus::Continue;
}


FilterMetadataStatus ModSecurityFilter::encodeMetadata(MetadataMap&) {
    return FilterMetadataStatus::Continue;
}

void ModSecurityFilter::setEncoderFilterCallbacks(StreamEncoderFilterCallbacks& callbacks) {
    encoder_callbacks_ = &callbacks;
}

bool ModSecurityFilter::intervention() {
    if (!status_.intervined && modsec_transaction_->m_it.disruptive) {
        // status_.intervined must be set to true before sendLocalReply to avoid reentrancy when encoding the reply
        status_.intervined = true;
        ENVOY_LOG(debug, "intervention");
        decoder_callbacks_->sendLocalReply(static_cast<Http::Code>(modsec_transaction_->m_it.status),
                                           "ModSecurity Action\n",
                                           [](Http::HeaderMap&) {}, absl::nullopt, "");
    }
    return status_.intervined;
}


FilterHeadersStatus ModSecurityFilter::getRequestHeadersStatus() {
    if (status_.intervined) {
        ENVOY_LOG(debug, "StopIteration");
        return FilterHeadersStatus::StopIteration;
    }
    if (status_.request_processed) {
        ENVOY_LOG(debug, "Continue");
        return FilterHeadersStatus::Continue;
    }
    // If disruptive, hold until status_.request_processed, otherwise let the data flow.
    ENVOY_LOG(debug, "RuleEngine");
    return modsec_transaction_->getRuleEngineState() == modsecurity::RulesSetProperties::EnabledRuleEngine ? 
                FilterHeadersStatus::StopIteration : 
                FilterHeadersStatus::Continue;
}

FilterDataStatus ModSecurityFilter::getRequestStatus() {
    if (status_.intervined) {
        ENVOY_LOG(debug, "StopIterationNoBuffer");
        return FilterDataStatus::StopIterationNoBuffer;
    }
    if (status_.request_processed) {
        ENVOY_LOG(debug, "Continue");
        return FilterDataStatus::Continue;
    }
    // If disruptive, hold until status_.request_processed, otherwise let the data flow.
    ENVOY_LOG(debug, "RuleEngine");
    return modsec_transaction_->getRuleEngineState() == modsecurity::RulesSetProperties::EnabledRuleEngine ? 
                FilterDataStatus::StopIterationAndBuffer :
                FilterDataStatus::Continue;
}

FilterHeadersStatus ModSecurityFilter::getResponseHeadersStatus() {
    if (status_.intervined || status_.response_processed) {
        // If intervined, let encodeData return the localReply
        ENVOY_LOG(debug, "Continue");
        return FilterHeadersStatus::Continue;
    }
    // If disruptive, hold until status_.response_processed, otherwise let the data flow.
    ENVOY_LOG(debug, "RuleEngine");
    return modsec_transaction_->getRuleEngineState() == modsecurity::RulesSetProperties::EnabledRuleEngine ? 
                FilterHeadersStatus::StopIteration : 
                FilterHeadersStatus::Continue;
}

FilterDataStatus ModSecurityFilter::getResponseStatus() {
    if (status_.intervined || status_.response_processed) {
        // If intervined, let encodeData return the localReply
        ENVOY_LOG(debug, "Continue");
        return FilterDataStatus::Continue;
    }
    // If disruptive, hold until status_.response_processed, otherwise let the data flow.
    ENVOY_LOG(debug, "RuleEngine");
    return modsec_transaction_->getRuleEngineState() == modsecurity::RulesSetProperties::EnabledRuleEngine ? 
                FilterDataStatus::StopIterationAndBuffer : 
                FilterDataStatus::Continue;

}

void ModSecurityFilter::_logCb(void *data, const void *ruleMessage) {
    auto filter_ = reinterpret_cast<ModSecurityFilter*>(data);

    filter_->logCb(reinterpret_cast<const modsecurity::RuleMessage*>(ruleMessage));
}

void ModSecurityFilter::logCb(const modsecurity::RuleMessage* ruleMessage) {
    if (ruleMessage == nullptr) {
        ENVOY_LOG(error, "ruleMessage == nullptr");
        return;
    }
    
    ENVOY_LOG(info, "Rule Id: {} phase: {}",
                    ruleMessage->m_ruleId,
                    ruleMessage->m_phase);
    ENVOY_LOG(info, "* {} action. {}",
                    // Note - since ModSecurity >= v3.0.3 disruptive actions do not invoke the callback
                    // see https://github.com/SpiderLabs/ModSecurity/commit/91daeee9f6a61b8eda07a3f77fc64bae7c6b7c36
                    ruleMessage->m_isDisruptive ? "Disruptive" : "Non-disruptive",
                    modsecurity::RuleMessage::log(ruleMessage));
    config_->webhook_fetcher()->invoke(getRuleMessageAsJsonString(ruleMessage));
}

} // namespace Http
} // namespace Envoy