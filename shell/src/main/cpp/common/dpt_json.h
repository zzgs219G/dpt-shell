//
// dpt_json.h — 极简 JSON 字段提取器（2026-10 体积优化，取代 nlohmann/json.hpp）
//
// 【为什么不用 nlohmann】
//   shell 只需要从 xixin_config 里读 8 个【扁平、已知名字】的字段：
//     app_name / acf_name / jni_cls_name / app_sign_sha256 /
//     dex_sign / junk_cls_name / risk_check_flags / use_inmemory_dex
//   而 json.hpp 是 22,875 行的通用库，模板实例化实测在 arm64 产物中
//   带来 ~149 KB（链接后：空工程 3.8 KB → 含 json 152.7 KB）。
//   这是 libxixin.so 754 KB 里最大的一块可回收体积。
//
// 【能力边界（有意为之，别当 bug）】
//   只支持【顶层对象】+ 【值为字符串/整数/布尔】的扁平结构，恰好覆盖
//   ShellConfig.toJson() 产出的形态。不支持：
//     · 嵌套对象/数组（遇到即跳过该字段值）
//     · 转义序列 \n \" \\ \uXXXX（值原样返回，不做反转义）
//   一旦打包侧把配置改成嵌套结构，这里必须同步升级——两侧契约见
//   docs/项目流程.md §5「shell config JSON 字段名」。
//
// 【安全边界】
//   配置来自 assets/xixin_config，已被 AES-CBC 解密且由打包器写入，
//   不属于不可信输入；本解析器仍对越界/截断做防御（返回空/默认值），
//   绝不越界读。
//
#pragma once

#include <string>
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace dpt {
namespace json {

// ── 结构校验（2026-10）──────────────────────────────────────────────
// 【为什么需要】原实现是 nlohmann::json::parse() 包在 try 里：解析失败即
// 抛异常，catch 后【所有字段都保持默认值】（因为赋值全在 parse 之后）。
// 若只做"逐字段扫描"，截断的 JSON 会把已读到的前半段当成有效值返回，
// 与旧行为不一致（对拍测试精确抓出过这个差异）。
// 所以先用本函数判定整份 JSON 是否合法；不合法则调用方整体走默认值。
//
// 支持全部 JSON 值类型（字符串/数字/true/false/null/对象/数组），
// 只判定合法性，不构造 DOM —— 无需堆分配，代码量约 100 行。
class Validator {
public:
    explicit Validator(const char *s, size_t n) : p_(s), end_(s + n) {}

    bool run() {
        skip_ws();
        if (!value()) return false;
        skip_ws();
        return p_ == end_;           // 尾部不得有多余字符
    }

private:
    const char *p_;
    const char *end_;

    void skip_ws() {
        while (p_ < end_ && (*p_ == ' ' || *p_ == '\t' || *p_ == '\r' || *p_ == '\n')) ++p_;
    }
    bool eof() const { return p_ >= end_; }
    char peek() const { return eof() ? '\0' : *p_; }

    bool value() {
        skip_ws();
        if (eof()) return false;
        char c = peek();
        if (c == '{') return object();
        if (c == '[') return array();
        if (c == '"') return string();
        if (c == 't') return literal("true");
        if (c == 'f') return literal("false");
        if (c == 'n') return literal("null");
        return number();
    }

    bool literal(const char *lit) {
        for (const char *q = lit; *q; ++q) {
            if (eof() || *p_ != *q) return false;
            ++p_;
        }
        return true;
    }

    bool string() {
        if (eof() || *p_ != '"') return false;
        ++p_;
        while (!eof()) {
            char c = *p_;
            if (c == '"') { ++p_; return true; }
            if (c == '\\') {
                ++p_;
                if (eof()) return false;
                char e = *p_;
                if (e == 'u') {
                    ++p_;
                    for (int i = 0; i < 4; ++i) {
                        if (eof()) return false;
                        char h = *p_;
                        bool ok = (h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') || (h >= 'A' && h <= 'F');
                        if (!ok) return false;
                        ++p_;
                    }
                    continue;
                }
                // \" \\ \/ \b \f \n \r \t
                if (e == '"' || e == '\\' || e == '/' || e == 'b' ||
                    e == 'f' || e == 'n' || e == 'r' || e == 't') { ++p_; continue; }
                return false;
            }
            if ((unsigned char) c < 0x20) return false;   // 未转义控制字符非法
            ++p_;
        }
        return false;                 // 未闭合
    }

    bool number() {
        const char *start = p_;
        if (!eof() && *p_ == '-') ++p_;
        if (eof()) return false;
        if (*p_ == '0') { ++p_; }
        else if (*p_ >= '1' && *p_ <= '9') { while (!eof() && *p_ >= '0' && *p_ <= '9') ++p_; }
        else return false;
        if (!eof() && *p_ == '.') {
            ++p_;
            if (eof() || !(*p_ >= '0' && *p_ <= '9')) return false;
            while (!eof() && *p_ >= '0' && *p_ <= '9') ++p_;
        }
        if (!eof() && (*p_ == 'e' || *p_ == 'E')) {
            ++p_;
            if (!eof() && (*p_ == '+' || *p_ == '-')) ++p_;
            if (eof() || !(*p_ >= '0' && *p_ <= '9')) return false;
            while (!eof() && *p_ >= '0' && *p_ <= '9') ++p_;
        }
        return p_ > start;
    }

    bool object() {
        if (eof() || *p_ != '{') return false;
        ++p_;
        skip_ws();
        if (!eof() && *p_ == '}') { ++p_; return true; }
        for (;;) {
            skip_ws();
            if (!string()) return false;          // 键必须是字符串
            skip_ws();
            if (eof() || *p_ != ':') return false;
            ++p_;
            if (!value()) return false;
            skip_ws();
            if (eof()) return false;
            if (*p_ == ',') { ++p_; continue; }
            if (*p_ == '}') { ++p_; return true; }
            return false;
        }
    }

    bool array() {
        if (eof() || *p_ != '[') return false;
        ++p_;
        skip_ws();
        if (!eof() && *p_ == ']') { ++p_; return true; }
        for (;;) {
            if (!value()) return false;
            skip_ws();
            if (eof()) return false;
            if (*p_ == ',') { ++p_; continue; }
            if (*p_ == ']') { ++p_; return true; }
            return false;
        }
    }
};

// 整份文本是否为合法的 JSON 值（顶层通常是对象）。
inline bool is_valid(const std::string &text) {
    if (text.empty()) return false;
    Validator v(text.data(), text.size());
    return v.run();
}

// 是否为一个合法的 JSON 顶层对象 —— read_shell_config 用这个。
inline bool is_valid_object(const std::string &text) {
    if (!is_valid(text)) return false;
    size_t i = 0;
    while (i < text.size() && (text[i] == ' ' || text[i] == '\t' ||
                               text[i] == '\r' || text[i] == '\n')) ++i;
    return i < text.size() && text[i] == '{';
}

// 在 src 指向的 [0, len) 范围内查找顶层键 key（形如 "key"），
// 返回其后 ":" 之后第一个非空白字符的位置；找不到返回 npos。
inline size_t find_value_start(const char *src, size_t len, const char *key) {
    if (src == nullptr || key == nullptr || len == 0) return std::string::npos;

    const size_t klen = strlen(key);
    size_t i = 0;
    while (i < len) {
        // 跳过非引号字符（键名一定以引号开头）
        if (src[i] != '"') { ++i; continue; }

        // 试探性匹配 "key"
        size_t j = i + 1;
        size_t k = 0;
        while (j < len && k < klen && src[j] == key[k]) { ++j; ++k; }
        if (k == klen && j < len && src[j] == '"') {
            // 键名后必须跟冒号（允许空白），否则可能是值里的同名字符串
            size_t m = j + 1;
            while (m < len && (src[m] == ' ' || src[m] == '\t' ||
                               src[m] == '\r' || src[m] == '\n')) ++m;
            if (m < len && src[m] == ':') {
                ++m;
                while (m < len && (src[m] == ' ' || src[m] == '\t' ||
                                   src[m] == '\r' || src[m] == '\n')) ++m;
                return (m < len) ? m : std::string::npos;
            }
        }
        ++i;  // 继续向后找下一个键
    }
    return std::string::npos;
}

// 取字符串字段；缺失或类型不符返回 def。
inline std::string get_string(const std::string &json, const char *key,
                              const std::string &def = std::string()) {
    size_t p = find_value_start(json.data(), json.size(), key);
    if (p == std::string::npos || json[p] != '"') return def;

    std::string out;
    size_t i = p + 1;
    while (i < json.size()) {
        char c = json[i];
        if (c == '\\') {           // 简单反转义：跳过转义符，保留原字符
            if (i + 1 < json.size()) { out.push_back(json[i + 1]); i += 2; continue; }
            break;
        }
        if (c == '"') return out;  // 正常结束
        out.push_back(c);
        ++i;
    }
    return def;                    // 截断（未闭合）→ 视为缺失
}

// 取无符号整数字段；缺失或非数字返回 def。
inline uint32_t get_uint(const std::string &json, const char *key, uint32_t def = 0) {
    size_t p = find_value_start(json.data(), json.size(), key);
    if (p == std::string::npos) return def;

    // 支持十进制与 0x 前缀十六进制（ShellConfig 目前只写十进制）
    bool negative = (json[p] == '-');
    if (negative) ++p;
    bool hex = (p + 1 < json.size() && json[p] == '0' &&
                (json[p + 1] == 'x' || json[p + 1] == 'X'));
    if (hex) p += 2;

    unsigned long long v = 0;
    bool any = false;
    while (p < json.size()) {
        char c = json[p];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (hex && c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (hex && c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else break;
        v = v * (hex ? 16 : 10) + (unsigned long long) d;
        any = true;
        ++p;
    }
    if (!any) return def;
    // 负数：与 nlohmann 的 value<uint32_t>() 行为对齐（按补码截断，
    // 例如 -1 → 4294967295）。ShellConfig 实际不会写负数，
    // 这里只是保持与旧实现完全等价，不引入行为漂移。
    if (negative) {
        long long sv = -(long long) v;
        return (uint32_t) (unsigned long long) sv;
    }
    return (uint32_t) v;
}

// 取布尔字段；支持 true/false 与 1/0。
inline bool get_bool(const std::string &json, const char *key, bool def = false) {
    size_t p = find_value_start(json.data(), json.size(), key);
    if (p == std::string::npos) return def;

    if (json.compare(p, 4, "true") == 0) return true;
    if (json.compare(p, 5, "false") == 0) return false;
    if (json[p] == '1') return true;
    if (json[p] == '0') return false;
    return def;
}

}  // namespace json
}  // namespace dpt
