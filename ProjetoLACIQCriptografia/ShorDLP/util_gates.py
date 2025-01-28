from qiskit import QuantumCircuit
from qiskit.circuit.library import QFT
from qiskit.visualization import plot_histogram
import numpy as np
from utils import converte_counts

def mod_exp_circuit(exp):
    U = QuantumCircuit(4)
    for it in range(exp):
        U.swap(2,3)
        U.swap(1,2)
        U.swap(0,1)
        for q in range(4):
            U.x(q)
    U = U.to_gate()
    U.name = f"{7}^{exp}mod15"
    return U.control()


def c_exp_15_mod31(exp):
    U = QuantumCircuit(5)
    for it in range(exp):
        U.swap(0, 1)
        U.swap(1, 2)
        U.swap(2, 3)
        U.swap(3, 4)
        for q in range(5):
            U.x(q)
    U = U.to_gate()
    U.name = f"  {15}^{exp}mod31"
    return U.control()

def c_exp_2_mod31(exp):
    U = QuantumCircuit(5)
    for it in range(exp):
        U.swap(0, 4)
        U.swap(3, 4)
        U.swap(2, 3)
        U.swap(1, 2)
        
    U = U.to_gate()
    U.name = f"  {2}^{exp}mod31"
    return U.control()


if __name__ == "__main__":
    from qiskit_aer import AerSimulator
    from qiskit import transpile, QuantumCircuit
    
    n_qubits = 6

    for exp in range(7):    
        qc = QuantumCircuit(n_qubits, n_qubits)
        qc.x([0,1])

        mod_circuit = c_exp_2_mod31(exp)
        qc.append(mod_circuit, range(n_qubits))
        qc.measure(range(1,n_qubits), range(n_qubits-1))
        #print(qc.draw("text"))
        simulator_aer = AerSimulator()
        qc_aer = transpile(qc, backend=simulator_aer)
        results = simulator_aer.run(qc_aer,shots=1024).result()
        counts = results.get_counts()
        counts = converte_counts(counts, double_outputs= False)
        print(counts)
