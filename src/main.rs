use std::cmp::Ordering;
use std::convert::From;
use std::fmt;
use std::net::{AddrParseError, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::u128;

#[derive(Debug, Clone, Copy)]
struct Ipv4Range {
    ip: u32,
    cidr: u8,
}

#[derive(Debug, Clone, Copy)]
struct Ipv6Range {
    ip: u128,
    cidr: u8,
}

impl PartialEq for Ipv4Range {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip
    }
}

impl PartialEq for Ipv6Range {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip
    }
}

impl Eq for Ipv4Range {}

impl Eq for Ipv6Range {}

impl PartialOrd for Ipv4Range {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.ip.partial_cmp(&other.ip)
    }
}

impl PartialOrd for Ipv6Range {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.ip.partial_cmp(&other.ip)
    }
}

impl Ord for Ipv4Range {
    fn cmp(&self, other: &Self) -> Ordering {
        self.ip.cmp(&other.ip)
    }
}

impl Ord for Ipv6Range {
    fn cmp(&self, other: &Self) -> Ordering {
        self.ip.cmp(&other.ip)
    }
}

#[derive(Debug, Clone)]
enum RangeParseError {
    MoreThanOneSlash,
    IpInvalid(AddrParseError),
    CidrInvalid,
}

trait IpRange: Sized {
    fn normalize(&mut self) -> &mut Self;
    fn _set_cidr(&mut self, c: u8) -> &mut Self;
    fn _reduce_cidr_by_one(&mut self) -> &mut Self;
    fn is_subset_of(&self, other: &Self) -> bool;
    fn is_superset_of(&self, other: &Self) -> bool;
    fn merge_with(&self, other: &Self) -> Option<Self>;
}

impl IpRange for Ipv4Range {
    fn normalize(&mut self) -> &mut Self {
        match self.cidr {
            0 => self.ip = 0,
            1..=31 => self.ip &= <u32>::max_value() << (32 - self.cidr),
            32 => {}
            _ => panic!("invalid CIDR size {}", self.cidr),
        };
        self
    }
    fn _set_cidr(&mut self, c: u8) -> &mut Self {
        self.cidr = c;
        self
    }
    fn _reduce_cidr_by_one(&mut self) -> &mut Self {
        match self.cidr {
            0 => self,
            n => {
                self.cidr = n - 1;
                self.normalize()
            }
        }
    }
    fn is_subset_of(&self, other: &Self) -> bool {
        self.cidr >= other.cidr && self.clone()._set_cidr(other.cidr).normalize().ip == other.ip
    }
    fn is_superset_of(&self, other: &Self) -> bool {
        self.cidr <= other.cidr && other.clone()._set_cidr(self.cidr).normalize().ip == self.ip
    }
    fn merge_with(&self, other: &Self) -> Option<Self> {
        if self.is_subset_of(other) {
            Some(*other)
        } else if other.is_subset_of(self) {
            Some(*self)
        } else if self.cidr != other.cidr {
            None
        } else if self.clone()._reduce_cidr_by_one().ip == other.clone()._reduce_cidr_by_one().ip {
            // two adjacent networks, e.g.
            //     192.168.1.0/24 and 192.168.0.0/24
            // can be merged to
            //     192.168.0.0/23
            Some(*(self.clone()._reduce_cidr_by_one()))
        } else {
            None
        }
    }
}

impl IpRange for Ipv6Range {
    fn normalize(&mut self) -> &mut Self {
        match self.cidr {
            0 => self.ip = 0,
            1..=127 => self.ip &= <u128>::max_value() << (128 - self.cidr),
            128 => {}
            _ => panic!("invalid CIDR size {}", self.cidr),
        };
        self
    }
    fn _set_cidr(&mut self, c: u8) -> &mut Self {
        self.cidr = c;
        self
    }
    fn _reduce_cidr_by_one(&mut self) -> &mut Self {
        match self.cidr {
            0 => self,
            n => {
                self.cidr = n - 1;
                self.normalize()
            }
        }
    }
    fn is_subset_of(&self, other: &Self) -> bool {
        self.cidr >= other.cidr && self.clone()._set_cidr(other.cidr).normalize().ip == other.ip
    }
    fn is_superset_of(&self, other: &Self) -> bool {
        self.cidr <= other.cidr && other.clone()._set_cidr(self.cidr).normalize().ip == self.ip
    }
    fn merge_with(&self, other: &Self) -> Option<Self> {
        if self.is_subset_of(other) {
            Some(*other)
        } else if other.is_subset_of(self) {
            Some(*self)
        } else if self.cidr != other.cidr {
            None
        } else if self.clone()._reduce_cidr_by_one().ip == other.clone()._reduce_cidr_by_one().ip {
            // two adjacent networks, e.g.
            //     192.168.1.0/24 and 192.168.0.0/24
            // can be merged to
            //     192.168.0.0/23
            Some(*(self.clone()._reduce_cidr_by_one()))
        } else {
            None
        }
    }
}

impl fmt::Display for Ipv4Range {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.ip), self.cidr)
    }
}

impl fmt::Display for Ipv6Range {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", Ipv6Addr::from(self.ip), self.cidr)
    }
}

impl FromStr for Ipv4Range {
    type Err = RangeParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let slashes: Vec<&str> = s.trim().split("/").collect();
        match (slashes.len(), slashes[0].parse::<Ipv4Addr>()) {
            (1..=2, Err(e)) => Err(RangeParseError::IpInvalid(e)),
            (1, Ok(i)) => Ok(Ipv4Range {
                ip: i.into(),
                cidr: 32,
            }),
            (2, Ok(i)) => match slashes[1].parse() {
                Ok(n) => match n {
                    0..=32 => {
                        let mut res = Ipv4Range {
                            ip: i.into(),
                            cidr: n,
                        };
                        res.normalize();
                        Ok(res)
                    }
                    _ => Err(RangeParseError::CidrInvalid),
                },
                Err(_) => Err(RangeParseError::CidrInvalid),
            },
            _ => Err(RangeParseError::MoreThanOneSlash),
        }
    }
}

impl FromStr for Ipv6Range {
    type Err = RangeParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let slashes: Vec<&str> = s.trim().split("/").collect();
        match (slashes.len(), slashes[0].parse::<Ipv6Addr>()) {
            (1, Err(e)) => Err(RangeParseError::IpInvalid(e)),
            (2, Err(e)) => Err(RangeParseError::IpInvalid(e)),
            (1, Ok(i)) => Ok(Ipv6Range {
                ip: i.into(),
                cidr: 32,
            }),
            (2, Ok(i)) => match slashes[1].parse() {
                Ok(n) => match n {
                    0..=128 => {
                        let mut res = Ipv6Range {
                            ip: i.into(),
                            cidr: n,
                        };
                        res.normalize();
                        Ok(res)
                    }
                    _ => Err(RangeParseError::CidrInvalid),
                },
                Err(_) => Err(RangeParseError::CidrInvalid),
            },
            _ => Err(RangeParseError::MoreThanOneSlash),
        }
    }
}

#[derive(Debug, Clone)]
struct IpRangeList {
    v4: Vec<Ipv4Range>,
    v6: Vec<Ipv6Range>,
}

impl fmt::Display for IpRangeList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ipv4: [")?;
        for i in &self.v4 {
            write!(f, "{}, ", i)?;
        }
        writeln!(f, "]")?;
        write!(f, "ipv6: [")?;
        for i in &self.v6 {
            write!(f, "{}, ", i)?;
        }
        write!(f, "]")?;
        Ok(())
    }
}

impl IpRangeList {
    fn new() -> Self {
        Self {
            v4: Vec::new(),
            v6: Vec::new(),
        }
    }

    fn empty(&mut self) -> &mut Self {
        self.v4 = Vec::new();
        self.v6 = Vec::new();
        self
    }

    fn add_list(&mut self, other: IpRangeList) -> &mut Self {
        for i in other.v4 {
            self.add_v4(i);
        }
        for i in other.v6 {
            self.add_v6(i);
        }
        self
    }

    fn substract_list(&mut self, other: IpRangeList) -> &mut Self {
        for i in other.v4 {
            self.substract_v4(i);
        }
        for i in other.v6 {
            self.substract_v6(i);
        }
        self
    }

    fn neighbor_merge_v4(&mut self, idx: usize) -> &mut Self {
        if idx > 0 {
            if let Some(r) = self.v4[idx - 1].merge_with(&self.v4[idx]) {
                // delete one, replace one
                self.v4.remove(idx - 1);
                self.v4[idx - 1] = r;
                // we have to try again, if we can merge the newly created one, too
                self.neighbor_merge_v4(idx - 1);
            } else {
            };
        } else {
        };
        if idx + 1 < self.v4.len() {
            if let Some(r) = self.v4[idx].merge_with(&self.v4[idx + 1]) {
                // delete one, replace one
                self.v4.remove(idx);
                self.v4[idx] = r;
                // we have to try again, if we can merge the newly created one, too
                self.neighbor_merge_v4(idx);
            } else {
            };
        } else {
        };
        self
    }

    fn add_v4(&mut self, i: Ipv4Range) -> &mut Self {
        match self.v4.binary_search_by(|probe| probe.cmp(&i)) {
            Ok(idx) => match i.merge_with(&self.v4[idx]) {
                Some(r) => {
                    self.v4[idx] = r;
                    self.neighbor_merge_v4(idx)
                }
                None => unreachable!(),
            },
            Err(idx) => {
                self.v4.insert(idx, i);
                self.neighbor_merge_v4(idx)
            }
        }
    }

    fn neighbor_merge_v6(&mut self, idx: usize) -> &mut Self {
        if idx > 0 {
            if let Some(r) = self.v6[idx - 1].merge_with(&self.v6[idx]) {
                // delete one, replace one
                self.v6.remove(idx - 1);
                self.v6[idx - 1] = r;
                // we have to try again, if we can merge the newly created one, too
                self.neighbor_merge_v6(idx - 1);
            } else {
            };
        } else {
        };
        if idx + 1 < self.v6.len() {
            if let Some(r) = self.v6[idx].merge_with(&self.v6[idx + 1]) {
                // delete one, replace one
                self.v6.remove(idx);
                self.v6[idx] = r;
                // we have to try again, if we can merge the newly created one, too
                self.neighbor_merge_v6(idx);
            } else {
            };
        } else {
        };
        self
    }

    fn add_v6(&mut self, i: Ipv6Range) -> &mut Self {
        match self.v6.binary_search_by(|probe| probe.cmp(&i)) {
            Ok(idx) => match i.merge_with(&self.v6[idx]) {
                Some(r) => {
                    self.v6[idx] = r;
                    self.neighbor_merge_v6(idx)
                }
                None => unreachable!(),
            },
            Err(idx) => {
                self.v6.insert(idx, i);
                self.neighbor_merge_v6(idx)
            }
        }
    }

    fn substract_v4(&mut self, i: Ipv4Range) -> &mut Self {
        for it in &mut self.v4 {
            unimplemented!()
        }
        self
    }

    fn substract_v6(&mut self, i: Ipv6Range) -> &mut Self {
        for it in &mut self.v6 {
            unimplemented!()
        }
        self
    }
}

fn main() {}

#[cfg(test)]
mod tests {
    extern crate rand;
    use self::rand::seq::SliceRandom;
    use self::rand::*;
    use super::*;

    #[test]
    fn parse_addresses() {
        let i: Ipv4Range = " 1.2.3.4 ".parse().unwrap();
        let i: Ipv4Range = " 1.2.3.4/0 ".parse().unwrap();
        let i: Ipv4Range = "1.2.3.4/32".parse().unwrap();
        let i: Ipv6Range = "::1".parse().unwrap();
        let i: Ipv6Range = "::1/0".parse().unwrap();
        let i: Ipv6Range = "::1/128".parse().unwrap();
    }

    #[test]
    fn sub_and_superset1a() {
        let i: Ipv4Range = "255.255.255.255/32".parse().unwrap();
        for c in 0..32 {
            let j = format!("255.255.255.255/{}", c);
            let j: Ipv4Range = j.parse().unwrap();

            assert!(i.is_superset_of(&i));
            assert!(i.is_subset_of(&i));
            assert!(j.is_superset_of(&j));
            assert!(j.is_subset_of(&j));

            assert!(!i.is_superset_of(&j));
            assert!(i.is_subset_of(&j));
            assert!(j.is_superset_of(&i));
            assert!(!j.is_subset_of(&i));
        }
    }

    #[test]
    fn sub_and_superset1b() {
        let i: Ipv4Range = "0.0.0.0/32".parse().unwrap();
        for c in 0..32 {
            let j = format!("0.0.0.0/{}", c);
            let j: Ipv4Range = j.parse().unwrap();

            assert!(i.is_superset_of(&i));
            assert!(i.is_subset_of(&i));
            assert!(j.is_superset_of(&j));
            assert!(j.is_subset_of(&j));

            assert!(!i.is_superset_of(&j));
            assert!(i.is_subset_of(&j));
            assert!(j.is_superset_of(&i));
            assert!(!j.is_subset_of(&i));
        }
    }

    #[test]
    fn sub_and_superset2a() {
        let i: Ipv6Range = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"
            .parse()
            .unwrap();
        for c in 0..127 {
            let j = format!("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/{}", c);
            let j: Ipv6Range = j.parse().unwrap();

            assert!(i.is_superset_of(&i));
            assert!(i.is_subset_of(&i));
            assert!(j.is_superset_of(&j));
            assert!(j.is_subset_of(&j));

            assert!(!i.is_superset_of(&j));
            assert!(i.is_subset_of(&j));
            assert!(j.is_superset_of(&i));
            assert!(!j.is_subset_of(&i));
        }
    }

    #[test]
    fn sub_and_superset2b() {
        let i: Ipv6Range = "::/128".parse().unwrap();
        for c in 0..127 {
            let j = format!("::/{}", c);
            let j: Ipv6Range = j.parse().unwrap();

            assert!(i.is_superset_of(&i));
            assert!(i.is_subset_of(&i));
            assert!(j.is_superset_of(&j));
            assert!(j.is_subset_of(&j));

            assert!(!i.is_superset_of(&j));
            assert!(i.is_subset_of(&j));
            assert!(j.is_superset_of(&i));
            assert!(!j.is_subset_of(&i));
        }
    }

    #[test]
    fn merge_with() {
        let a: Ipv4Range = "192.168.0.0/24".parse().unwrap();
        let b: Ipv4Range = "192.168.1.0/24".parse().unwrap();
        let c: Ipv4Range = "192.168.2.0/24".parse().unwrap();
        let d: Ipv4Range = "192.168.0.0/23".parse().unwrap();
        for i in [a, b, c, d].iter() {
            assert!(i.merge_with(i).unwrap() == *i);
        }
        assert!(a.merge_with(&b).unwrap() == d);
        assert!(a.merge_with(&c).is_none());
        assert!(a.merge_with(&d).unwrap() == d);
        assert!(b.merge_with(&a).unwrap() == d);
        assert!(b.merge_with(&c).is_none());
        assert!(b.merge_with(&d).unwrap() == d);
        assert!(c.merge_with(&a).is_none());
        assert!(c.merge_with(&b).is_none());
        assert!(c.merge_with(&d).is_none());
        assert!(d.merge_with(&a).unwrap() == d);
        assert!(d.merge_with(&b).unwrap() == d);
        assert!(d.merge_with(&c).is_none());
    }
    #[test]
    fn add_v4() {
        let mut l = IpRangeList::new();
        let mut tmp: Vec<Ipv4Range> = Vec::new();
        for a in 0..256 {
            let j = format!("192.168.{}.1/24", a);
            let j: Ipv4Range = j.parse().unwrap();
            tmp.push(j);
        }
        tmp.shuffle(&mut rand::thread_rng());
        for i in 0..256 {
            l.add_v4(tmp[i]);
            println!("***************************************");
            println!("{}", tmp[i]);
            println!("{}", l);
        }
        assert!(l.v4.len() == 1);
        assert!(
            l.v4[0]
                == Ipv4Range {
                    ip: 192 * 256 * 256 * 256 + 168 * 256 * 256,
                    cidr: 16
                }
        );
    }

    fn _generate_random_list() -> IpRangeList {
        match rand::thread_rng().gen_range(1..=2) {
            1..=2 => (),
            _ => unreachable!(),
        }
        IpRangeList::new()
    }
}
