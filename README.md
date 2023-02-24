# dns_name

Robust domain name parsing using the Public Suffix List

This library allows you to easily and accurately parse any given domain
name.

```rust
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
```
