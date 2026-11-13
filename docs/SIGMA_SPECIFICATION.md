# Supported Sigma Specification and Laboratory Scope

**Project:** SOC Detection Engineering Lab  
**Author:** Mannan Shah (@Mannan55)  
**Standard:** Sigma Detection Format  

---

## 1. Supported Syntax and Modifiers

The laboratory testing engine (`engine/rule_matcher.py`) implements a core subset of the official Sigma specification optimized for fast, deterministic unit testing against normalized JSON security telemetry.

### 1.1 Field Modifiers
* **Default (No modifier):** Exact string matching (case-insensitive).
* **`|contains`:** Substring search (case-insensitive).
* **`|startswith`:** Prefix matching (case-insensitive).
* **`|endswith`:** Suffix matching (case-insensitive).
* **Lists of Values:** When a field target is a list, the engine treats it as an `OR` condition, matching if any element satisfies the modifier.

### 1.2 Detection Conditions
* **`selection`:** Single detection block evaluation.
* **`selection and not filter`:** Positive selection with exclusion filter.
* **`all of selection* and not filter*`:** Conjunction of all selection blocks (`selection_img`, `selection_encoded`, etc.) combined with negation of exclusion filters.
* **`1 of selection* and not filter*`:** Disjunction of selection blocks combined with negation of exclusion filters.

---

## 2. Documented Unsupported Features and Scope Boundaries

The internal test engine is intentionally focused on single-event Detection-as-Code verification. The following advanced Sigma extensions are documented as out-of-scope for the stateless unit matcher:

1. **Stateful Multi-Event Time Aggregations:**
   - Aggregations such as `count() by User > 10 in 5m` require a streaming stateful correlation engine (such as the detection engine in AuthGuard-X or an enterprise SIEM) rather than a stateless unit test runner.
2. **Regex Modifiers (`|re`):**
   - Complex regular expressions are avoided in baseline Sigma rules to prevent Regular Expression Denial of Service (ReDoS) and maintain portability across SIEM backends.
3. **Numeric Range Modifiers (`|gt`, `|lt`, `|gte`):**
   - Byte count and process ID range evaluations are handled via categorical filters.

---

## 3. Real-World Accuracy and Synthetic Laboratory Disclosure

* **Laboratory Context:** The 100% detection rate and 0% false positive rate achieved in this laboratory reflect deterministic verification against curated synthetic unit test fixtures.
* **Production Reality:** In live enterprise environments with diverse third-party administrative software, detection rules require ongoing threshold tuning, baseline whitelisting, and correlation against host context to manage real-world false positive rates.
