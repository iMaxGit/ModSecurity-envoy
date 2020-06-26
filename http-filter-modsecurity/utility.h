#pragma once

#include <string>

#include "modsecurity/modsecurity.h"
#include "modsecurity/rule_message.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ModSecurity {

/**
 * Converts a RuleMessage to json 
 * @return A json string
 */
std::string getRuleMessageAsJsonString(const modsecurity::RuleMessage* ruleMessage);

} // namespace ModSecurity
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
