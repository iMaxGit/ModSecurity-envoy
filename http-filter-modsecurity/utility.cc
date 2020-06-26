#include "utility.h"
#include "common/protobuf/protobuf.h"
#include "common/protobuf/utility.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurity {

std::string getRuleMessageAsJsonString(const modsecurity::RuleMessage* ruleMessage) {
    ProtobufWkt::Struct document;
    auto* document_fields = document.mutable_fields();
    (*document_fields)["accuracy"] = ValueUtil::numberValue(ruleMessage->m_accuracy);
    (*document_fields)["clientIpAddress"] = ValueUtil::stringValue(*ruleMessage->m_clientIpAddress);
    (*document_fields)["data"] = ValueUtil::stringValue(ruleMessage->m_data);
    (*document_fields)["id"] = ValueUtil::stringValue(*ruleMessage->m_id);
    (*document_fields)["isDisruptive"] = ValueUtil::boolValue(ruleMessage->m_isDisruptive);
    (*document_fields)["match"] = ValueUtil::stringValue(ruleMessage->m_match);
    (*document_fields)["maturity"] = ValueUtil::numberValue(ruleMessage->m_maturity);
    (*document_fields)["message"] = ValueUtil::stringValue(ruleMessage->m_message);
    (*document_fields)["noAuditLog"] = ValueUtil::boolValue(ruleMessage->m_noAuditLog);
    (*document_fields)["phase"] = ValueUtil::numberValue(ruleMessage->m_phase);
    (*document_fields)["reference"] = ValueUtil::stringValue(ruleMessage->m_reference);
    (*document_fields)["rev"] = ValueUtil::stringValue(ruleMessage->m_rev);
    (*document_fields)["ruleFile"] = ValueUtil::stringValue(*ruleMessage->m_ruleFile);
    (*document_fields)["ruleId"] = ValueUtil::numberValue(ruleMessage->m_ruleId);
    (*document_fields)["ruleLine"] = ValueUtil::numberValue(ruleMessage->m_ruleLine);
    (*document_fields)["saveMessage"] = ValueUtil::boolValue(ruleMessage->m_saveMessage);
    (*document_fields)["serverIpAddress"] = ValueUtil::stringValue(*ruleMessage->m_serverIpAddress);
    (*document_fields)["severity"] = ValueUtil::numberValue(ruleMessage->m_severity);
    (*document_fields)["uriNoQueryStringDecoded"] = ValueUtil::stringValue(*ruleMessage->m_uriNoQueryStringDecoded);
    (*document_fields)["ver"] = ValueUtil::stringValue(ruleMessage->m_ver);
    std::vector<ProtobufWkt::Value> tag_array;
    for (const auto& tag : ruleMessage->m_tags) {
        tag_array.push_back(ValueUtil::stringValue(tag));
    }
    (*document_fields)["tags"] = ValueUtil::listValue(tag_array);
    return MessageUtil::getJsonStringFromMessage(document);
}

} // namespace ModSecurity
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy