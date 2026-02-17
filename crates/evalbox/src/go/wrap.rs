//! Go code wrapping utilities.

use regex::Regex;

pub const AUTO_IMPORTS: &[(&str, &str)] = &[
    ("fmt", "fmt"),
    ("strings", "strings"),
    ("strconv", "strconv"),
    ("json", "encoding/json"),
    ("http", "net/http"),
    ("io", "io"),
    ("os", "os"),
    ("time", "time"),
    ("math", "math"),
    ("rand", "math/rand"),
    ("sort", "sort"),
    ("regexp", "regexp"),
    ("bytes", "bytes"),
    ("bufio", "bufio"),
    ("errors", "errors"),
    ("context", "context"),
    ("sync", "sync"),
    ("filepath", "path/filepath"),
    ("path", "path"),
    ("log", "log"),
    ("testing", "testing"),
    ("reflect", "reflect"),
    ("unicode", "unicode"),
    ("runtime", "runtime"),
];

pub fn wrap_go_code(code: &str, auto_wrap: bool, auto_import: bool) -> String {
    if !auto_wrap {
        return code.to_string();
    }

    let mut result = String::new();
    let code_trimmed = code.trim();

    let has_pkg = has_package_decl(code_trimmed);
    let has_main = has_main_func(code_trimmed);
    let has_imp = has_imports(code_trimmed);

    if has_pkg && has_main {
        return code.to_string();
    }

    if !has_pkg {
        result.push_str("package main\n\n");
    }

    if auto_import && !has_imp {
        let imports = detect_imports(code_trimmed);
        if !imports.is_empty() {
            result.push_str("import (\n");
            for imp in imports {
                result.push_str(&format!("\t\"{imp}\"\n"));
            }
            result.push_str(")\n\n");
        }
    }

    if !has_main {
        result.push_str("func main() {\n");
        for line in code_trimmed.lines() {
            result.push('\t');
            result.push_str(line);
            result.push('\n');
        }
        result.push_str("}\n");
    } else {
        result.push_str(code_trimmed);
        result.push('\n');
    }

    result
}

fn detect_imports(code: &str) -> Vec<String> {
    let mut imports = Vec::new();
    let re = Regex::new(r"\b([a-z]+)\.([A-Z][a-zA-Z0-9]*)").unwrap();

    for cap in re.captures_iter(code) {
        let pkg = &cap[1];
        if let Some((_, import_path)) = AUTO_IMPORTS.iter().find(|(name, _)| *name == pkg) {
            let import = import_path.to_string();
            if !imports.contains(&import) {
                imports.push(import);
            }
        }
    }

    imports
}

fn has_main_func(code: &str) -> bool {
    let re = Regex::new(r"(?m)^func\s+main\s*\(\s*\)").unwrap();
    re.is_match(code)
}

fn has_package_decl(code: &str) -> bool {
    let re = Regex::new(r"(?m)^package\s+").unwrap();
    re.is_match(code)
}

fn has_imports(code: &str) -> bool {
    let re = Regex::new(r"(?m)^import\s+").unwrap();
    re.is_match(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_imports_single() {
        let code = r#"fmt.Println("hello")"#;
        let imports = detect_imports(code);
        assert!(imports.contains(&"fmt".to_string()));
        assert_eq!(imports.len(), 1);
    }

    #[test]
    fn test_detect_imports_multiple() {
        let code = r#"fmt.Println("hello")
json.Marshal(x)
strings.ToUpper("test")"#;
        let imports = detect_imports(code);
        assert!(imports.contains(&"fmt".to_string()));
        assert!(imports.contains(&"encoding/json".to_string()));
        assert!(imports.contains(&"strings".to_string()));
    }

    #[test]
    fn test_detect_imports_no_duplicates() {
        let code = r#"fmt.Println("a")
fmt.Println("b")
fmt.Printf("%s", "c")"#;
        let imports = detect_imports(code);
        assert_eq!(imports.iter().filter(|&i| i == "fmt").count(), 1);
    }

    #[test]
    fn test_detect_imports_empty() {
        let code = "x := 1 + 2";
        let imports = detect_imports(code);
        assert!(imports.is_empty());
    }

    #[test]
    fn test_has_main_func() {
        assert!(has_main_func("func main() { }"));
        assert!(has_main_func("func main() {}"));
        assert!(has_main_func("func main(){}"));
        assert!(has_main_func("\nfunc main() {\n}"));
    }

    #[test]
    fn test_has_main_func_negative() {
        assert!(!has_main_func("func notmain() {}"));
        assert!(!has_main_func("fmt.Println(main)"));
        assert!(!has_main_func("// func main() {}"));
        assert!(!has_main_func("func main2() {}"));
    }

    #[test]
    fn test_has_package_decl() {
        assert!(has_package_decl("package main"));
        assert!(has_package_decl("package foo\n"));
        assert!(!has_package_decl("// package main"));
        assert!(!has_package_decl("import \"package\""));
    }

    #[test]
    fn test_has_imports() {
        assert!(has_imports("import \"fmt\""));
        assert!(has_imports("import (\n\"fmt\"\n)"));
        assert!(!has_imports("// import \"fmt\""));
        assert!(!has_imports("fmt.Println()"));
    }

    #[test]
    fn test_wrap_simple_expression() {
        let code = r#"fmt.Println("hello")"#;
        let wrapped = wrap_go_code(code, true, true);

        assert!(wrapped.contains("package main"));
        assert!(wrapped.contains("import ("));
        assert!(wrapped.contains("\"fmt\""));
        assert!(wrapped.contains("func main()"));
        assert!(wrapped.contains("fmt.Println(\"hello\")"));
    }

    #[test]
    fn test_wrap_preserves_complete_program() {
        let code = r#"package main

import "fmt"

func main() {
    fmt.Println("hello")
}"#;
        let wrapped = wrap_go_code(code, true, true);
        assert_eq!(wrapped.trim(), code.trim());
    }

    #[test]
    fn test_wrap_disabled() {
        let code = r#"fmt.Println("hello")"#;
        let wrapped = wrap_go_code(code, false, false);
        assert_eq!(wrapped, code);
    }

    #[test]
    fn test_wrap_no_auto_import() {
        let code = r#"fmt.Println("hello")"#;
        let wrapped = wrap_go_code(code, true, false);

        assert!(wrapped.contains("package main"));
        assert!(wrapped.contains("func main()"));
        assert!(!wrapped.contains("import"));
    }

    #[test]
    fn test_wrap_with_existing_func_main() {
        let code = r#"func main() {
    fmt.Println("hello")
}"#;
        let wrapped = wrap_go_code(code, true, true);

        assert!(wrapped.contains("package main"));
        assert_eq!(wrapped.matches("func main()").count(), 1);
    }
}
