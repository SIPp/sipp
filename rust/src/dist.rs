//! SIPp's statistical distributions, for <pause> and <sample>: the
//! parameters and meanings of its CSample classes (GSL's samplers).

use std::f64::consts::PI;

/// A source of uniform numbers in [0, 1).
pub trait Unit {
    fn unit(&mut self) -> f64;
}

#[derive(Debug, Clone, PartialEq)]
pub enum Dist {
    Fixed(f64),
    Uniform { min: f64, max: f64 },
    Normal { mean: f64, stdev: f64 },
    /// Of the underlying normal, as gsl_ran_lognormal.
    LogNormal { mean: f64, stdev: f64 },
    Exponential { mean: f64 },
    Weibull { lambda: f64, k: f64 },
    Pareto { k: f64, x_m: f64 },
    GPareto { shape: f64, scale: f64, location: f64 },
    Gamma { k: f64, theta: f64 },
    NegBin { p: f64, n: f64 },
}

impl Dist {
    /// parse_distribution(): `distribution=` and its parameters, read by
    /// `param`. None when there is no distribution= (the caller decides).
    pub fn parse(get: impl Fn(&str) -> Option<String>) -> Result<Option<Dist>, String> {
        let Some(name) = get("distribution") else { return Ok(None) };
        let title = match name.as_str() {
            "fixed" => "Fixed",
            "uniform" => "Uniform",
            "normal" => "Normal",
            "lognormal" => "Lognormal",
            "exponential" => "Exponential",
            "weibull" => "Weibull",
            "pareto" => "Pareto",
            "gpareto" => "Generalized Pareto",
            "gamma" => "Gamma",
            "negbin" => "Negative Binomial",
            // SIPp prints "(null)" here, not the name.
            other => return Err(format!("Unknown distribution: {other}")),
        };
        // xp_get_double().
        let p = |key: &str| -> Result<f64, String> {
            let v = get(key).ok_or_else(|| format!("{title} distribution is missing the required '{key}' parameter."))?;
            match crate::posix::strtod(&v) {
                (n, "") if !v.is_empty() => Ok(n),
                _ => Err(format!("{title} distribution '{key}' parameter, \"{v}\" is not a floating point number!")),
            }
        };
        Ok(Some(match name.as_str() {
            "fixed" => Dist::Fixed(p("value")?),
            "uniform" => Dist::Uniform { min: p("min")?, max: p("max")? },
            "normal" => Dist::Normal { mean: p("mean")?, stdev: p("stdev")? },
            "lognormal" => Dist::LogNormal { mean: p("mean")?, stdev: p("stdev")? },
            "exponential" => Dist::Exponential { mean: p("mean")? },
            "weibull" => Dist::Weibull { lambda: p("lambda")?, k: p("k")? },
            "pareto" => Dist::Pareto { k: p("k")?, x_m: p("x_m")? },
            "gpareto" => Dist::GPareto { shape: p("shape")?, scale: p("scale")?, location: p("location")? },
            "gamma" => Dist::Gamma { k: p("k")?, theta: p("theta")? },
            _ => {
                let n = p("n")?;
                Dist::NegBin { p: p("p")?, n }
            }
        }))
    }

    /// timeDescr(): how the screen shows it.
    pub fn describe(&self) -> String {
        let t = time_string;
        match *self {
            Dist::Fixed(v) => t(v),
            Dist::Uniform { min, max } => format!("{}/{}", t(min), t(max)),
            Dist::Normal { mean, stdev } => format!("N({},{})", t(mean), t(stdev)),
            Dist::LogNormal { mean, stdev } => format!("LN({},{})", t(mean), t(stdev)),
            Dist::Exponential { mean } => format!("Exp({})", t(mean)),
            Dist::Weibull { lambda, k } => format!("Wb({},{})", t(lambda), t(k)),
            Dist::Pareto { k, x_m } => format!("P({},{})", t(k), t(x_m)),
            Dist::GPareto { shape, scale, location } => format!("P({},{},{})", t(shape), t(scale), t(location)),
            Dist::Gamma { k, theta } => format!("G({},{})", t(k), t(theta)),
            Dist::NegBin { p, n } => format!("NB({},{})", t(p), t(n)),
        }
    }

    /// textDescr(): the parameters as numbers, as a <sample> shows them.
    pub fn text(&self) -> String {
        match *self {
            Dist::Fixed(v) => format!("{v:.6}"),
            Dist::Uniform { min, max } => format!("{min:.6}/{max:.6}"),
            Dist::Normal { mean, stdev } => format!("N({mean:.3},{stdev:.3})"),
            Dist::LogNormal { mean, stdev } => format!("LN({mean:.3},{stdev:.3})"),
            Dist::Exponential { mean } => format!("Exp({mean:.6})"),
            Dist::Weibull { lambda, k } => format!("Wb({lambda:.3},{k:.3})"),
            Dist::Pareto { k, x_m } => format!("P({k:.3},{x_m:.3})"),
            Dist::GPareto { shape, scale, location } => format!("P({shape:.3},{scale:.3},{location:.3})"),
            Dist::Gamma { k, theta } => format!("G({k:.3},{theta:.3})"),
            Dist::NegBin { p, n } => format!("NB({p:.3},{n:.3})"),
        }
    }

    /// cdfInv(0.99), which SIPp adds up into the scenario's duration.
    pub fn p99(&self) -> f64 {
        // The standard normal's 99th percentile.
        const Z: f64 = 2.326_347_874;
        match *self {
            Dist::Fixed(v) => v,
            Dist::Uniform { min, max } => min + (max - min) * 0.99,
            Dist::Normal { mean, stdev } => mean + Z * stdev,
            Dist::LogNormal { mean, stdev } => (mean + Z * stdev).exp(),
            Dist::Exponential { mean } => -mean * 0.01f64.ln(),
            Dist::Weibull { lambda, k } => lambda * (-(0.01f64.ln())).powf(1.0 / k),
            Dist::Pareto { k, x_m } => x_m * 0.01f64.powf(-1.0 / k),
            Dist::GPareto { shape, scale, location } => location + scale * (0.99f64.powf(-shape) - 1.0) / shape,
            // Wilson and Hilferty.
            Dist::Gamma { k, theta } => k * theta * (1.0 - 1.0 / (9.0 * k) + Z * (1.0 / (9.0 * k)).sqrt()).powi(3),
            Dist::NegBin { .. } => 0.0,
        }
    }

    pub fn sample(&self, rng: &mut impl Unit) -> f64 {
        match *self {
            Dist::Fixed(v) => v,
            Dist::Uniform { min, max } => min + rng.unit() * (max - min),
            Dist::Normal { mean, stdev } => mean + stdev * gaussian(rng),
            Dist::LogNormal { mean, stdev } => (mean + stdev * gaussian(rng)).exp(),
            Dist::Exponential { mean } => -mean * positive(rng).ln(),
            Dist::Weibull { lambda, k } => lambda * (-positive(rng).ln()).powf(1.0 / k),
            Dist::Pareto { k, x_m } => x_m * positive(rng).powf(-1.0 / k),
            Dist::GPareto { shape, scale, location } => location + scale * (rng.unit().powf(-shape) - 1.0) / shape,
            Dist::Gamma { k, theta } => gamma(rng, k) * theta,
            Dist::NegBin { p, n } => {
                let mu = gamma(rng, n) * (1.0 - p) / p;
                poisson(rng, mu)
            }
        }
    }
}

/// time_string(): milliseconds as the screens show them.
pub fn time_string(ms: f64) -> String {
    if ms < 10000.0 {
        if (ms + 0.9999) as i64 == ms as i64 {
            format!("{}ms", ms as i64)
        } else if ms < 1000.0 {
            format!("{ms:.2}ms")
        } else {
            format!("{ms:.1}ms")
        }
    } else if ms < 60000.0 {
        format!("{:.1}s", ms / 1000.0)
    } else if ms < 3_600_000.0 {
        let s = (ms / 1000.0) as u64;
        format!("{}:{:02}", s / 60, s % 60)
    } else {
        let s = (ms / 1000.0) as u64;
        format!("{}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
    }
}

/// In (0, 1], for logarithms.
fn positive(rng: &mut impl Unit) -> f64 {
    1.0 - rng.unit()
}

/// Box-Muller.
fn gaussian(rng: &mut impl Unit) -> f64 {
    (-2.0 * positive(rng).ln()).sqrt() * (2.0 * PI * rng.unit()).cos()
}

/// Marsaglia and Tsang, with the a < 1 boost.
fn gamma(rng: &mut impl Unit, a: f64) -> f64 {
    if a < 1.0 {
        return gamma(rng, a + 1.0) * positive(rng).powf(1.0 / a);
    }
    let d = a - 1.0 / 3.0;
    let c = 1.0 / (9.0 * d).sqrt();
    loop {
        let (x, v) = loop {
            let x = gaussian(rng);
            let v = 1.0 + c * x;
            if v > 0.0 {
                break (x, v * v * v);
            }
        };
        let u = positive(rng);
        if u < 1.0 - 0.0331 * x.powi(4) || u.ln() < 0.5 * x * x + d * (1.0 - v + v.ln()) {
            return d * v;
        }
    }
}

/// Knuth's product method for small means, the gamma/binomial split
/// (GSL's own) for large ones.
fn poisson(rng: &mut impl Unit, mut mu: f64) -> f64 {
    let mut k = 0.0;
    while mu > 10.0 {
        let m = (mu * 7.0 / 8.0).floor();
        let x = gamma(rng, m);
        if x >= mu {
            return k + binomial(rng, m - 1.0, mu / x);
        }
        k += m;
        mu -= x;
    }
    let limit = (-mu).exp();
    let mut prod = 1.0;
    loop {
        prod *= rng.unit();
        if prod <= limit {
            return k;
        }
        k += 1.0;
    }
}

fn binomial(rng: &mut impl Unit, n: f64, p: f64) -> f64 {
    (0..n as u64).filter(|_| rng.unit() < p).count() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Xorshift(u64);
    impl Unit for Xorshift {
        fn unit(&mut self) -> f64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 >> 11) as f64 / (1u64 << 53) as f64
        }
    }

    fn mean_of(d: &Dist) -> f64 {
        let mut rng = Xorshift(0x9E3779B97F4A7C15);
        (0..200_000).map(|_| d.sample(&mut rng)).sum::<f64>() / 200_000.0
    }

    #[test]
    fn samples_have_the_expected_means() {
        let close = |d: Dist, want: f64| {
            let got = mean_of(&d);
            assert!((got - want).abs() < want.abs() * 0.02 + 0.02, "{d:?}: mean {got}, expected {want}");
        };
        close(Dist::Fixed(42.0), 42.0);
        close(Dist::Uniform { min: 100.0, max: 200.0 }, 150.0);
        close(Dist::Normal { mean: 1000.0, stdev: 100.0 }, 1000.0);
        close(Dist::LogNormal { mean: 1.0, stdev: 0.5 }, (1.0f64 + 0.125).exp());
        close(Dist::Exponential { mean: 300.0 }, 300.0);
        // Weibull(1, 1) is the exponential with mean 1.
        close(Dist::Weibull { lambda: 1.0, k: 1.0 }, 1.0);
        close(Dist::Pareto { k: 3.0, x_m: 2.0 }, 3.0);
        close(Dist::Gamma { k: 2.5, theta: 4.0 }, 10.0);
        close(Dist::Gamma { k: 0.5, theta: 2.0 }, 1.0);
        // n (1 - p) / p
        close(Dist::NegBin { p: 0.25, n: 5.0 }, 15.0);
        close(Dist::NegBin { p: 0.02, n: 3.0 }, 147.0);
    }

    #[test]
    fn parse_reads_sipps_parameter_names() {
        let attrs = [("distribution", "weibull"), ("lambda", "3"), ("k", "1.5")];
        let get = |k: &str| attrs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string());
        assert_eq!(Dist::parse(get), Ok(Some(Dist::Weibull { lambda: 3.0, k: 1.5 })));
        assert_eq!(Dist::parse(|_| None), Ok(None));
        assert!(Dist::parse(|k| (k == "distribution").then(|| "normal".to_string())).is_err());
    }
}
