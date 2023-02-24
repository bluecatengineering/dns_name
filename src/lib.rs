//! Robust domain name parsing using the Public Suffix List
//!
//! This library allows you to easily and accurately parse any given domain
//! name.
//! ```
//! let list = List::from_path("suffix-list.txt").unwrap();

//! let domain = list.parse_dns_name("www.example.com")?;
//! assert_eq!(domain.name(), "www.example.com");
//! assert_eq!(domain.rname(), "moc.elpmaxe.www");
//! assert_eq!(domain.root(), Some("example.com"));
//! assert_eq!(domain.suffix(), Some("com"));
//! assert_eq!(domain.registrable(), Some("example"));

//! // 2-level TLD
//! let domain = list.parse_dns_name("wWw.BlUeCaTnEtWoRkS.Uk.CoM.")?;
//! assert_eq!(domain.name(), "www.bluecatnetworks.uk.com.");
//! assert_eq!(domain.rname(), ".moc.ku.skrowtentaceulb.www");
//! assert_eq!(domain.root(), Some("bluecatnetworks.uk.com."));
//! assert_eq!(domain.suffix(), Some("uk.com."));
//! assert_eq!(domain.registrable(), Some("bluecatnetworks"));

//! // the root name
//! let domain = list.parse_dns_name(".")?;
//! assert_eq!(domain.name(), ".");
//! assert_eq!(domain.rname(), ".");
//! assert_eq!(domain.root(), None);
//! assert_eq!(domain.suffix(), None);
//! assert_eq!(domain.registrable(), None);
//! ```

use std::{
    collections::HashMap,
    fmt,
    fs::File,
    io::{self, Read},
    ops::Range,
    path::Path,
};

const PREVAILING_STAR_RULE: &str = "*";

#[derive(Debug)]
// A node leaf
struct ListLeaf {
    is_exception_rule: bool,
}

impl ListLeaf {
    /// Creates a new `ListLeaf`
    fn new(is_exception_rule: bool) -> Self {
        Self { is_exception_rule }
    }
}

#[derive(Debug)]
/// A List node
struct ListNode {
    children: HashMap<String, ListNode>,
    leaf: Option<ListLeaf>,
}

impl ListNode {
    /// Creates a new `ListNode`
    fn new() -> Self {
        Self {
            children: HashMap::new(),
            leaf: None,
        }
    }
}

/// Stores the public suffix list
#[derive(Debug)]
pub struct List {
    root: ListNode,
}

/// Holds information about a particular DNS name
///
/// This is created by `List::parse_domain`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsName {
    /// full name: foo.example.com
    name: String,
    /// name, reversed by character: moc.elpmaxe.oof
    rname: String,
    /// suffix: com
    suffix: Option<Range<usize>>,
    /// root: example.com
    root: Option<Range<usize>>,
    /// registrable: example
    registrable: Option<Range<usize>>,
}

impl List {
    fn append(&mut self, mut rule: &str) -> io::Result<()> {
        let mut is_exception_rule = false;
        if rule.starts_with('!') {
            is_exception_rule = true;
            rule = &rule[1..];
        }

        let mut current = &mut self.root;
        for label in rule.rsplit('.') {
            if label.is_empty() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid rule"));
            }

            let cur = current;
            current = cur
                .children
                .entry(label.to_owned())
                .or_insert_with(ListNode::new);
        }

        current.leaf = Some(ListLeaf::new(is_exception_rule));

        Ok(())
    }

    fn build(res: &str) -> io::Result<List> {
        let mut list = List::empty();
        for rule in res.split(',') {
            list.append(rule)?;
        }
        if list.root.children.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "invalid list"));
        }
        list.append(PREVAILING_STAR_RULE)?; // add the default rule
        Ok(list)
    }

    /// Creates an empty List without any rules
    pub fn empty() -> List {
        List {
            root: ListNode::new(),
        }
    }

    /// Fetch the list from a local file
    pub fn from_path<P: AsRef<Path>>(path: P) -> io::Result<List> {
        File::open(path)
            .and_then(|mut data| {
                let mut res = String::new();
                data.read_to_string(&mut res)?;
                Ok(res)
            })
            .and_then(|s| s.parse::<List>())
    }

    /// Build the list from the result of anything that implements
    /// `std::io::Read`
    ///
    /// If you don't already have your list on the filesystem but want to use
    /// your own library to fetch the list you can use this method so you
    /// don't have to save it first.
    pub fn from_reader<R: Read>(mut reader: R) -> io::Result<List> {
        let mut res = String::new();
        reader.read_to_string(&mut res)?;
        Self::build(&res)
    }

    /// Parses a domain using the list (API backwards compat)
    pub fn parse_domain(&self, domain: &str) -> io::Result<DnsName> {
        DnsName::parse(domain, self)
    }

    /// Parses a DNS name using the list
    pub fn parse_dns_name(&self, domain: &str) -> io::Result<DnsName> {
        DnsName::parse(domain, self)
    }

    /// Converts a TrustDNS [`Name`] into a `DnsName`
    ///
    /// [`Name`]: trust_dns_proto::rr::domain::Name
    pub fn from_trustdns_name(
        &self,
        name: &trust_dns_proto::rr::domain::Name,
    ) -> io::Result<DnsName> {
        self.parse_dns_name(&name.to_ascii())
    }
}

impl std::str::FromStr for List {
    type Err = io::Error;

    fn from_str(s: &str) -> io::Result<Self> {
        Self::build(s)
    }
}

impl DnsName {
    fn new(name: String, suffix: Option<Range<usize>>, root: Option<Range<usize>>) -> DnsName {
        let rname = name.chars().rev().collect::<String>();

        let registrable = if let (Some(suffix), Some(root)) = (suffix.as_ref(), root.as_ref()) {
            Some(Range {
                start: root.start,
                end: suffix.start - 1,
            })
        } else {
            None
        };

        DnsName {
            name,
            rname,
            root,
            suffix,
            registrable,
        }
    }

    /// Counts the length of 1 or more labels, counting from reverse
    ///
    /// ("b.example.uk.com", 2) -> "uk.com" -> 6
    fn subname_length(input: &str, s_len: usize) -> usize {
        let len = input
            .trim_end_matches('.')
            .split('.')
            .rev()
            .take(s_len)
            .fold(0, |acc, part| acc + part.len());

        // Add in "." seperators
        len + (s_len - 1)
    }

    /// Finds a match in the Public Suffix list
    fn find_match(input: &str, list: &List) -> io::Result<DnsName> {
        // root domain is permitted
        if input.len() == 1 && input.starts_with('.') {
            return Ok(DnsName::new(input.to_owned(), None, None));
        }

        // a name cannot start with '.'
        if input.starts_with('.') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid name"));
        }

        let mut longest_valid = None;
        let mut current = &list.root;
        let mut s_labels_len = 0;

        let input = input.to_ascii_lowercase();
        let domain = input.trim_end_matches('.');

        // very basic sanity check the labels
        for label in domain.split('.') {
            if label.is_empty() || label.contains(' ') {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid name"));
            }
        }

        for label in domain.rsplit('.') {
            if let Some(child) = current.children.get(label) {
                current = child;
                s_labels_len += 1;
            } else if let Some(child) = current.children.get("*") {
                // wildcard rule
                current = child;
                s_labels_len += 1;
            } else {
                // no match rules
                break;
            }

            if let Some(list_leaf) = &current.leaf {
                longest_valid = Some((list_leaf, s_labels_len));
            }
        }

        match longest_valid {
            Some((leaf, suffix_len)) => {
                let suffix_len = if leaf.is_exception_rule {
                    suffix_len - 1
                } else {
                    suffix_len
                };

                let suffix = Some(Range {
                    start: domain.len() - Self::subname_length(domain, suffix_len),
                    end: domain.len(),
                });

                let d_labels_len = domain.match_indices('.').count() + 1;

                let registrable = if d_labels_len > suffix_len {
                    Some(Range {
                        start: domain.len() - Self::subname_length(domain, suffix_len + 1),
                        end: domain.len(),
                    })
                } else {
                    None
                };

                Ok(DnsName::new(input, suffix, registrable))
            }
            None => Ok(DnsName::new(input, None, None)),
        }
    }

    /// Parses a DNS name using the list
    fn parse(domain: &str, list: &List) -> io::Result<DnsName> {
        Self::find_match(domain, list)
    }

    /// Get the DNS name
    ///
    /// ```rust
    /// # use dns_name::{List, DnsName};
    /// let list = List::empty();
    /// let name = list.parse_domain("www.example.com").unwrap();
    /// assert_eq!(name.name(), "www.example.com");
    /// ```
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the DNS name in character reversed order
    /// ```rust
    /// # use dns_name::{List, DnsName};
    /// let list = List::empty();
    /// let name = list.parse_domain("www.example.com").unwrap();
    /// assert_eq!(name.rname(), "moc.elpmaxe.www");
    /// ```
    pub fn rname(&self) -> &str {
        &self.rname
    }

    /// Gets the root domain portion of the Name
    /// ```should_panic
    /// # use dns_name::{List, DnsName};
    /// let list = List::empty();
    /// let name = list.parse_domain("www.example.com").unwrap();
    /// assert_eq!(name.root(), Some("example.com"));
    /// ```
    pub fn root(&self) -> Option<&str> {
        match self.root {
            Some(ref root) if root.start < self.name.len() => Some(&self.name[root.start..]),
            _ => None,
        }
    }

    /// Gets the suffix portion of the Name
    /// ```should_panic
    /// # use dns_name::{List, DnsName};
    /// let list = List::empty();
    /// let name = list.parse_domain("www.example.com").unwrap();
    /// assert_eq!(name.root(), Some("com"));
    /// ```
    pub fn suffix(&self) -> Option<&str> {
        match self.suffix {
            Some(ref suffix) if suffix.start < self.name.len() => Some(&self.name[suffix.start..]),
            _ => None,
        }
    }

    /// Gets the registrable portion of the Name
    /// ```should_panic
    /// # use dns_name::{List, DnsName};
    /// let list = List::empty();
    /// let name = list.parse_domain("www.example.com").unwrap();
    /// assert_eq!(name.root(), Some("example"));
    /// ```
    pub fn registrable(&self) -> Option<&str> {
        match self.registrable {
            Some(ref registrable)
                if registrable.start < self.name.len() && registrable.end < self.name.len() =>
            {
                Some(&self.name[registrable.start..registrable.end])
            }
            _ => None,
        }
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name.trim_end_matches('.').to_lowercase())
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn dnsname() -> Result<(), std::io::Error> {
        let list = List::from_path("suffix-list.txt").unwrap();

        let domain = list.parse_dns_name("www.example.com")?;
        assert_eq!(domain.name(), "www.example.com");
        assert_eq!(domain.rname(), "moc.elpmaxe.www");
        assert_eq!(domain.root(), Some("example.com"));
        assert_eq!(domain.suffix(), Some("com"));
        assert_eq!(domain.registrable(), Some("example"));

        // 2-level TLD
        let domain = list.parse_dns_name("wWw.BlUeCaTnEtWoRkS.Uk.CoM.")?;
        assert_eq!(domain.name(), "www.bluecatnetworks.uk.com.");
        assert_eq!(domain.rname(), ".moc.ku.skrowtentaceulb.www");
        assert_eq!(domain.root(), Some("bluecatnetworks.uk.com."));
        assert_eq!(domain.suffix(), Some("uk.com."));
        assert_eq!(domain.registrable(), Some("bluecatnetworks"));

        // the root name
        let domain = list.parse_dns_name(".")?;
        assert_eq!(domain.name(), ".");
        assert_eq!(domain.rname(), ".");
        assert_eq!(domain.root(), None);
        assert_eq!(domain.suffix(), None);
        assert_eq!(domain.registrable(), None);

        Ok(())
    }

    #[test]
    fn trustdns() -> Result<(), std::io::Error> {
        use std::str::FromStr;
        use trust_dns_proto::rr::domain::Name;
        let list = List::from_path("suffix-list.txt").unwrap();

        let domain = list.from_trustdns_name(&Name::from_str("a.b.c").unwrap())?;
        assert_eq!(domain.name(), "a.b.c");
        assert_eq!(domain.rname(), "c.b.a");
        assert_eq!(domain.root(), Some("b.c"));
        assert_eq!(domain.suffix(), Some("c"));

        // conversion to ascii
        let domain = list.from_trustdns_name(&Name::from_str("a.♥").unwrap())?;
        assert_eq!(domain.name(), "a.xn--g6h");
        assert_eq!(domain.root(), Some("a.xn--g6h"));
        assert_eq!(domain.suffix(), Some("xn--g6h"));

        Ok(())
    }

    fn make_list() -> List {
        let list = List::from_path("suffix-list.txt").unwrap();

        let body = File::open("tests.txt")
            .and_then(|mut data| {
                let mut res = String::new();
                data.read_to_string(&mut res)?;
                Ok(res)
            })
            .unwrap();

        let mut parse = false;

        for (i, line) in body.lines().enumerate() {
            match line {
                line if line.trim().is_empty() => {
                    parse = true;
                    continue;
                }
                line if line.starts_with("//") => {
                    continue;
                }
                line => {
                    if !parse {
                        continue;
                    }
                    let mut test = line.split_whitespace().peekable();
                    if test.peek().is_none() {
                        continue;
                    }
                    let input = match test.next() {
                        Some("null") => "",
                        Some(res) => res,
                        None => {
                            panic!("line {i} of the test file doesn't seem to be valid");
                        }
                    };
                    let (expected_root, expected_suffix) = match test.next() {
                        Some("null") => (None, None),
                        Some(root) => {
                            let suffix = {
                                let parts: Vec<&str> = root.split('.').rev().collect();
                                parts[..parts.len() - 1]
                                    .iter()
                                    .rev()
                                    .copied()
                                    .collect::<Vec<_>>()
                                    .join(".")
                            };
                            (Some(root.to_string()), Some(suffix.to_string()))
                        }
                        None => {
                            panic!("line {i} of the test file doesn't seem to be valid");
                        }
                    };
                    let (found_root, found_suffix) = match list.parse_domain(input) {
                        Ok(domain) => {
                            let found_root = domain.root().map(|found| found.to_string());
                            let found_suffix = domain.suffix().map(|found| found.to_string());
                            (found_root, found_suffix)
                        }
                        Err(_) => (None, None),
                    };
                    if expected_root != found_root
                        || (expected_root.is_some() && expected_suffix != found_suffix)
                    {
                        let msg = format!(
                            "\n\nGiven `{}`:\nWe expected root domain to be `{:?}` and suffix be \
                             `{:?}`\nBut instead, we have `{:?}` as root domain and `{:?}` as \
                             suffix.\nWe are on line {} of `test_psl.txt`.\n\n",
                            input,
                            expected_root,
                            expected_suffix,
                            found_root,
                            found_suffix,
                            i + 1
                        );
                        panic!("{}", msg);
                    }
                }
            }
        }
        list
    }

    #[test]
    fn allow_qualified_domain_names() {
        let list = make_list();
        assert!(list.parse_domain("example.com.").is_ok());
    }

    #[test]
    fn allow_single_label_trailing_dot() {
        let list = make_list();
        assert!(list.parse_domain("com.").is_ok());
    }

    #[test]
    fn have_suffix_single_label_domains() {
        let list = make_list();
        let domains = vec![
            // real TLDs
            "com",
            "saarland",
            "museum.",
            // non-existant TLDs
            "localhost",
            "madeup",
            "with-dot.",
        ];
        for domain in domains {
            let res = list.parse_domain(domain).unwrap();
            assert_eq!(res.suffix(), Some(domain));
            assert!(res.root().is_none());
        }
    }

    #[test]
    fn no_empty_labels() {
        let list = make_list();
        assert!(list.parse_domain("exa..mple.com").is_err());
    }
    #[test]
    fn no_spaces() {
        let list = make_list();
        assert!(list.parse_domain("exa mple.com").is_err());
    }

    #[test]
    fn no_fwd_slash() {
        let list = make_list();
        assert!(list.parse_domain("exa/mple.com").is_ok());
    }

    #[test]
    fn no_ipv4() {
        let list = make_list();
        assert!(list.parse_domain("127.38.53.247").is_ok());
    }
    #[test]
    fn no_ipv6() {
        let list = make_list();
        assert!(list
            .parse_domain("fd79:cdcb:38cc:9dd:f686:e06d:32f3:c123")
            .is_ok());
    }
    #[test]
    fn label_max_127() {
        let list = make_list();
        let mut too_many_labels_domain = String::from("a");
        for _ in 0..126 {
            too_many_labels_domain.push_str(".a");
        }
        too_many_labels_domain.push_str(".com");
        assert!(list.parse_domain(&too_many_labels_domain).is_ok());
    }

    #[test]
    fn choose_longest_valid() {
        let list = make_list();
        let domain = list.parse_domain("foo.builder.nu").unwrap();
        assert_eq!(Some("nu"), domain.suffix());
        assert_eq!(Some("builder.nu"), domain.root());

        let domain = list.parse_domain("foo.fbsbx.com").unwrap();
        assert_eq!(Some("com"), domain.suffix());
        assert_eq!(Some("fbsbx.com"), domain.root());
    }

    #[test]
    fn allow_num_only_labels() {
        let list = make_list();
        assert!(list.parse_domain("127.com").is_ok());
    }
}
