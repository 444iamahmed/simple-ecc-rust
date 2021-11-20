use num_bigint::BigInt;
use num_traits::Num;
use num_traits::One;
use num_traits::Zero;
use std::io;
use std::str::FromStr;


#[derive(Clone, PartialEq, Debug)]
struct Point {
    x: BigInt,
    y: BigInt,
}



#[derive(Clone)]
struct ECC {
    a: BigInt,
    b: BigInt,
    p: BigInt,
    g: Point,
    k: BigInt,
}

impl ECC {
    fn reduce_modp(&self, x: BigInt) -> BigInt {
        x % self.p.clone()
    }

    fn equal_modp(&self, x: BigInt, y: BigInt) -> bool {
        self.reduce_modp(y - x) == BigInt::zero()
    }

    fn inverse_modp(&self, x: BigInt) -> Option<BigInt> {
        if self.reduce_modp(x.clone()) == BigInt::zero() {
            return None;
        }
        Some(x.modpow(&(self.p.clone() - BigInt::from(2)), &self.p)) //(self.p - BigInt::from(2))))
    }

    fn apply_bin_operation(
        &self,
        p1_maybe: Option<Point>,
        p2_maybe: Option<Point>,
        op: Box<dyn Fn(Point, Point) -> Point> ,
    ) -> Option<Point> {
        if let Some(p1) = p1_maybe {
            if let Some(p2) = p2_maybe {
                return Some(op(p1, p2));
            }
            return None;
        }
        return None;
    }

    fn addition_util(&self, p1: Point, p2: Point) -> Point {
        let lambda: BigInt;

        // let p1 = p1.clone();
        // let p2 = p2.clone();

        if p1 == p2 {
            lambda = self.reduce_modp(
                (BigInt::from(3) * p1.x.clone() * p1.x.clone() + self.a.clone())
                    / (BigInt::from(2) * p1.y.clone()),
            );
        } else {
            lambda =
                self.reduce_modp((p2.y.clone() - p1.y.clone()) / (p2.x.clone() - p1.x.clone()));
        }

        let x3 = self.reduce_modp(lambda.clone() * lambda.clone() - p1.x.clone() - p2.x.clone());
        let y3 = self.reduce_modp(lambda.clone() * (p1.x.clone() - x3.clone()) - p1.y.clone());

        return Point {
            x: x3.clone(),
            y: y3.clone(),
        };
    }
    fn subtraction_util(&self, p1: Point, p2: Point) -> Point {
        self.addition_util(p1, Point { x: p2.x, y: -p2.y })
    }

    fn is_point_valid(&self, p: Point) -> bool {
        return self.equal_modp(
            p.y.pow(2),
            p.x.pow(3) + self.a.clone() * p.x.clone() + self.b.clone(),
        );
    }

    fn scalar_multiplication(&self, n: BigInt, p: Option<Point>) -> Point {
        let mut new_point = p;
        let mut i = BigInt::from(1);

        let closure = |temp_p1, temp_p2| -> Point { self.addition_util(temp_p1, temp_p2) };
        while i <= n {
            new_point = self.apply_bin_operation(new_point.clone(), new_point.clone(), Box::new(closure));
            i += BigInt::one();
        }

        new_point.unwrap()
    }

    fn g_at(&self, n: BigInt) -> Point {
        self.scalar_multiplication(n, Some(self.g.clone()))
    }

    fn encrypt(&self, m: Point, pub_k: Point) -> Point {
        let closure = |temp_p1, temp_p2| self.addition_util(temp_p1, temp_p2);
        self.apply_bin_operation(
            Some(m),
            Some(self.scalar_multiplication(self.k.clone(), Some(pub_k))),
            Box::new(closure),
        )
        .unwrap()
    }

    fn decrypt(&self, c: Point) -> Point {
        self.scalar_multiplication(self.k.clone(), Some(c))
    }
}

fn compute_pk(ecc: &ECC) -> Point {
    ecc.g_at(ecc.k.clone())
}
fn main() {
    let mut temp_line = String::new();
    println!("Hello!\nWelcome to simECC..\nPlease enter your private key:");

    io::stdin()
        .read_line(&mut temp_line)
        .expect("Failure to read key\n");

    // temp_line.trim()
    let input_k = BigInt::from_str(temp_line.trim()).unwrap();
    let new_ecc = ECC {
        a: BigInt::zero(),
        b: BigInt::from(7),
        p: BigInt::from_str_radix(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            16,
        )
        .unwrap(),
        g: Point {
            x: BigInt::from_str_radix(
                "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                16,
            )
            .unwrap(),
            y: BigInt::from_str_radix(
                "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
                16,
            )
            .unwrap(),
        },
        k: input_k,
    };

    let public_key = compute_pk(&new_ecc);

    let m = new_ecc.g_at(BigInt::from(7));

    println!("{}", new_ecc.is_point_valid(m.clone()));
    println!("{:?}", m);
    // // println!("{:?}", new_ecc.decrypt(new_ecc.encrypt(m, public_key));
    println!("{:?}", new_ecc.decrypt(new_ecc.encrypt(m, public_key)));
}

// fn main() {
//     println!("Hello")
// }
