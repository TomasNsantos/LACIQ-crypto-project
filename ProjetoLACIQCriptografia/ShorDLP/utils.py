from fractions import Fraction
import sympy
from sympy import mod_inverse


def break_output(output : str):
    #output = output[::-1]
    n = len(output)//2
    first, second = output[:n], output[n:]
    
    return int(first,2), int(second,2)

def converte_counts(counts : dict, double_outputs : bool = True):
    
    if double_outputs:
        return {break_output(k):v for k,v in counts.items()}
    else:
        return {int(k,2) : v for k,v in counts.items()}

def bivariate_function(x1, x2, g, A, N):
    """
    Bivariate function f(x1, x2) = g^x1 * A^x2 mod N.
    """
    return (pow(g, x1, N) * pow(A, x2, N)) % N


def find_period(c, n_qubits, g, p):
    """Find the period using continued fractions.
    inputs:
    c: shor output
    n_qubits: n° qubits used by the QFT
    g and p: g ^ T mod p
    output T: g ^ T mod p == 1
    """
    #x = c / (2**n_qubits)  # The rational approximation
    #terms = continued_fraction(x)
    terms = sympy.continued_fraction_periodic(c,2**n_qubits)
    for i in range(1, len(terms) + 1):
        # Generate the convergent as a Fraction
        frac = Fraction(0)  # Start with zero
        for term in reversed(terms[:i]):
            if frac == 0:  # First iteration
                frac = Fraction(term)
            else:
                frac = Fraction(1, frac) + term
            if frac.denominator > p:
                continue
        q = frac.denominator  # Get the denominator (candidate period)
        
        # Check if q is the period
        if q > 0 and pow(g, q, p) == 1:
            print(f"output c: {g}^{q}mod{p} == 1")
            return q
    return None  # Return None if no period is found




def compute_results(input_dict, t, q_minus_1):
    results = {}
    for (w1, w2), c in input_dict:
        if c > t and w1 > 0 and w2 > 0:
            try:
                # Compute modular inverse of w2 mod (q-1)
                w2_inv = mod_inverse(w2, q_minus_1)
                # Calculate -w1 / w2 mod (q-1)
                result = (-w1 * w2_inv) % q_minus_1
                results[(w1, w2)] = {f"log": result, "count": c}
            except ValueError:
                # Skip if modular inverse does not exist
                print(f"Skipping ({w1}, {w2}) as modular inverse does not exist")
    return results

