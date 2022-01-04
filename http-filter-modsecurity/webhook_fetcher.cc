#include "webhook_fetcher.h"

/* v1.18
#include "common/buffer/buffer_impl.h"
#include "common/common/enum_to_int.h"
#include "common/common/hex.h"
#include "common/crypto/utility.h"
#include "common/http/headers.h"
#include "common/http/utility.h"
#include "common/crypto/utility.h"
*/

/* v1.20 */
#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/enum_to_int.h"
#include "source/common/common/hex.h"
#include "source/common/http/headers.h"
#include "source/common/http/utility.h"
#include "source/common/crypto/utility.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurity {

WebhookFetcher::WebhookFetcher(Upstream::ClusterManager& cm,
                              const envoy::config::core::v3::HttpUri& uri,
                              const std::string& secret, 
                              WebhookFetcherCallback& callback)
    : cm_(cm), uri_(uri), secret_(secret.cbegin(), secret.cend()), callback_(callback) {}

WebhookFetcher::~WebhookFetcher() {}

void WebhookFetcher::invoke(const std::string& body) {
  if (!cm_.getThreadLocalCluster(uri_.cluster())) {
    ENVOY_LOG(error, "Webhook can't be invoked. cluster '{}' not found", uri_.cluster());
    return;
  }

  Http::RequestMessagePtr message = Http::Utility::prepareHeaders(uri_);
  message->headers().setReferenceMethod(Http::Headers::get().MethodValues.Post);
  message->headers().setReferenceContentType(Http::Headers::get().ContentTypeValues.Json);
  message->headers().setContentLength(body.size());
  message->body().add(body);
  if (secret_.size()) {
    auto& crypto_util = Envoy::Common::Crypto::UtilitySingleton::get();
    // Add digest to headers
    message->headers().addCopy(WebhookHeaders::get().SignatureType, WebhookConstants::get().Sha256Hmac);
    message->headers().addCopy(WebhookHeaders::get().SignatureValue, Hex::encode(crypto_util.getSha256Hmac(secret_, body)));
  }

  ENVOY_LOG(debug, "Webhook [uri = {}]: start", uri_.uri());
  const auto thread_local_cluster = cm_.getThreadLocalCluster(uri_.cluster());
  if (thread_local_cluster != nullptr) {
    thread_local_cluster->httpAsyncClient().send(
      std::move(message), *this,
      Http::AsyncClient::RequestOptions().setTimeout(
        std::chrono::milliseconds(DurationUtil::durationToMilliseconds(uri_.timeout()))));
  }
}

void WebhookFetcher::onSuccess(const Http::AsyncClient::Request&,
                               Http::ResponseMessagePtr&& response) {
  const uint64_t status_code = Http::Utility::getResponseStatus(response->headers());
  if (status_code == enumToInt(Http::Code::OK)) {
    ENVOY_LOG(debug, "Webhook [uri = {}]: success", uri_.uri());
    callback_.onSuccess(response);
  } else {
    ENVOY_LOG(debug, "Webhook [uri = {}]: bad response status code {}", uri_.uri(),
              status_code);
    callback_.onFailure(FailureReason::BadHttpStatus);
  }

}

void WebhookFetcher::onFailure(const Http::AsyncClient::Request&,
                               Http::AsyncClient::FailureReason reason) {
  ENVOY_LOG(debug, "Webhook [uri = {}]: network error {}", uri_.uri(), enumToInt(reason));
  callback_.onFailure(FailureReason::Network);
}

} // namespace ModSecurity
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
