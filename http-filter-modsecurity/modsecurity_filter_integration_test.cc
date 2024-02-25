#include "test/integration/http_integration.h"
#include "test/integration/utility.h"

namespace Envoy
{
  class HttpFilterSampleIntegrationTest : public HttpIntegrationTest,
                                          public testing::TestWithParam<Network::Address::IpVersion>
  {
  public:
    HttpFilterSampleIntegrationTest()
        : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam()) {}
    /**
     * Initializer for an individual integration test.
     */
    void SetUp() override { initialize(); }

    void initialize() override
    {
      config_helper_.addFilter("{ name: sample, config: { key: via, val: sample-filter } }");
      HttpIntegrationTest::initialize();
    }
  };

  INSTANTIATE_TEST_SUITE_P(IpVersions, HttpFilterSampleIntegrationTest,
                           testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

  TEST_P(HttpFilterSampleIntegrationTest, Test1)
  {
    Http::TestRequestHeaderMapImpl headers{{":method", "GET"}, {":path", "/"}, {":authority", "host"}};

    IntegrationCodecClientPtr codec_client;
    FakeHttpConnectionPtr fake_upstream_connection;
    IntegrationStreamDecoderPtr response(new IntegrationStreamDecoder(*dispatcher_));
    FakeStreamPtr request_stream;

    codec_client = makeHttpConnection(lookupPort("http"));
    // codec_client->makeHeaderOnlyRequest(headers, *response);
    response = codec_client->makeHeaderOnlyRequest(headers);
    // fake_upstream_connection = fake_upstreams_[0]->waitForHttpConnection(*dispatcher_);
    ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection));
    // request_stream = fake_upstream_connection->waitForNewStream(*dispatcher_);
    ASSERT_TRUE(fake_upstream_connection->waitForNewStream(*dispatcher_, request_stream));
    ASSERT_TRUE(request_stream->waitForEndStream(*dispatcher_));
    ASSERT_TRUE(response->waitForEndStream());

    EXPECT_EQ("sample-filter",
              request_stream->headers().get(Http::LowerCaseString("via"))[0]->value().getStringView());

    codec_client->close();
  }
} // namespace Envoy
