#include "waf_config.h"

#include <gtest/gtest.h>

#include <string>

namespace {

TEST(WafConfig, DefaultJsonConfigIsValidJson) {
  const char* cfg = defaultWafJsonConfig();
  ASSERT_NE(cfg, nullptr);
  EXPECT_NE(std::string(cfg).find("directives_map"), std::string::npos);
}

TEST(WafConfig, PlainTextConfigPassesThrough) {
  const std::string cfg = "SecRuleEngine On\n";
  std::string rules;
  std::string error;
  ASSERT_TRUE(expandWafConfiguration(cfg, rules, error));
  EXPECT_EQ(rules, "SecRuleEngine On");
  EXPECT_TRUE(error.empty());
}

TEST(WafConfig, EmptyConfigFails) {
  std::string rules;
  std::string error;
  EXPECT_FALSE(expandWafConfiguration("   ", rules, error));
  EXPECT_FALSE(error.empty());
}

TEST(WafConfig, JsonWithDemoIncludeExpands) {
  const std::string cfg = R"({
    "directives_map": {
      "default": [
        "Include @demo-conf",
        "SecDebugLogLevel 1"
      ]
    },
    "default_directives": "default"
  })";
  std::string rules;
  std::string error;
  ASSERT_TRUE(expandWafConfiguration(cfg, rules, error)) << error;
  EXPECT_NE(rules.find("SecRuleEngine On"), std::string::npos);
  EXPECT_NE(rules.find("SecDebugLogLevel 1"), std::string::npos);
}

TEST(WafConfig, MissingProfileFails) {
  const std::string cfg = R"({
    "directives_map": {
      "other": ["SecRuleEngine On"]
    },
    "default_directives": "default"
  })";
  std::string rules;
  std::string error;
  EXPECT_FALSE(expandWafConfiguration(cfg, rules, error));
  EXPECT_NE(error.find("directives_map profile not found"), std::string::npos);
}

TEST(WafConfig, UnknownIncludeFails) {
  const std::string cfg = R"({
    "directives_map": {
      "default": ["Include @does-not-exist"]
    },
    "default_directives": "default"
  })";
  std::string rules;
  std::string error;
  EXPECT_FALSE(expandWafConfiguration(cfg, rules, error));
  EXPECT_NE(error.find("unsupported Include target"), std::string::npos);
}

TEST(WafConfig, AllowFallbackDefaultsFalse) {
  const std::string cfg = R"({"directives_map":{"default":["SecRuleEngine On"]},"default_directives":"default"})";
  EXPECT_FALSE(wafConfigAllowsFallback(cfg));
}

TEST(WafConfig, AllowFallbackTrueWhenSet) {
  const std::string cfg =
      R"({"allow_fallback":true,"directives_map":{"default":["SecRuleEngine On"]},"default_directives":"default"})";
  EXPECT_TRUE(wafConfigAllowsFallback(cfg));
}

TEST(WafConfig, PlainTextDoesNotAllowFallback) {
  EXPECT_FALSE(wafConfigAllowsFallback("SecRuleEngine On"));
}

TEST(WafConfig, ParseMetricLabels) {
  const std::string cfg = R"({
    "metric_labels": {
      "owner": "modsec-wasm",
      "identifier": "test"
    },
    "directives_map": {"default": ["SecRuleEngine On"]},
    "default_directives": "default"
  })";
  WafMetricOptions opts;
  ASSERT_TRUE(parseWafMetricOptions(cfg, opts));
  ASSERT_EQ(opts.labels.size(), 2u);
  EXPECT_EQ(opts.labels[0].first, "owner");
  EXPECT_EQ(opts.labels[0].second, "modsec-wasm");
  EXPECT_EQ(opts.labels[1].first, "identifier");
  EXPECT_EQ(opts.labels[1].second, "test");
}

TEST(WafConfig, ParseMetricToggles) {
  const std::string cfg = R"({
    "metrics_per_rule_id": false,
    "metrics_rule_tags": false,
    "directives_map": {"default": ["SecRuleEngine On"]},
    "default_directives": "default"
  })";
  WafMetricOptions opts;
  ASSERT_TRUE(parseWafMetricOptions(cfg, opts));
  EXPECT_FALSE(opts.per_rule_id);
  EXPECT_FALSE(opts.rule_tags);
}

TEST(WafConfig, ApplyConfigurationInvokesLoader) {
  const std::string cfg = "SecRuleEngine DetectionOnly\n";
  struct Ctx {
    int chunks{0};
    std::string payload;
  } ctx;
  auto loader = +[](const char* label, const char* data, std::size_t size, void* user, std::string& error) -> bool {
    (void)label;
    (void)error;
    auto* c = static_cast<Ctx*>(user);
    ++c->chunks;
    c->payload.assign(data, size);
    return true;
  };
  std::string error;
  ASSERT_TRUE(applyWafConfiguration(cfg, loader, &ctx, error));
  EXPECT_EQ(ctx.chunks, 1);
  EXPECT_EQ(ctx.payload, "SecRuleEngine DetectionOnly");
}

}  // namespace