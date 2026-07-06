// Vendored smoke-corpus fixture (D-03 / SC3). Small, self-contained,
// license-clean C++ source: string utility helpers. No external build
// dependency. See test_scenarios/smoke/SOURCES.md for provenance/pinning.
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

namespace strutil {

std::string to_lower(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

std::string trim(const std::string& s) {
    size_t b = 0;
    size_t e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) {
        ++b;
    }
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) {
        --e;
    }
    return s.substr(b, e - b);
}

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> parts;
    std::string cur;
    for (char c : s) {
        if (c == sep) {
            parts.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    parts.push_back(cur);
    return parts;
}

std::string join(const std::vector<std::string>& parts, const std::string& sep) {
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) {
            out += sep;
        }
        out += parts[i];
    }
    return out;
}

bool starts_with(const std::string& s, const std::string& prefix) {
    if (prefix.size() > s.size()) {
        return false;
    }
    return std::equal(prefix.begin(), prefix.end(), s.begin());
}

int count_char(const std::string& s, char target) {
    return static_cast<int>(std::count(s.begin(), s.end(), target));
}

} // namespace strutil
