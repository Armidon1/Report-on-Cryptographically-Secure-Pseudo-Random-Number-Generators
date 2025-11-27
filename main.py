import time
import sys
import os
import matplotlib.pyplot as plt

# Prova a importare la libreria crittografica
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("ERRORE CRITICO: La libreria 'cryptography' non è installata.")
    print("Esegui questo comando nel terminale: pip install cryptography")
    sys.exit(1)


class BBS_Generator:
    def __init__(self, length_bits):
        self.length = length_bits
        self.p = 30000000091 #prime to q such that is congruent to 3 mod 4
        self.q = 40000000003 #prime to p such that is congruent to 3 mod 4
        self.n = self.p * self.q
        self.s = 1234567 #such that GCD(s, n) = 1
        self.state = pow(self.s, 2, self.n)

    def generate(self):
        bits = []
        start_time = time.perf_counter() 
        current_x = self.state
        
        for _ in range(self.length):
            current_x = pow(current_x, 2, self.n)
            bits.append(current_x % 2)
            
        end_time = time.perf_counter()
        return bits, end_time - start_time


class RSA_Generator:
    def __init__(self, length_bits):
        self.length = length_bits
        self.p = 30000000091 #prime
        self.q = 40000000003 #prime
        self.n = self.p * self.q
        self.e = 65537 #such that GCD(e, (p-1)∙(q-1)) = 1
        self.s = 1234567 #seed
        self.state = self.s 

    def generate(self):
        bits = []
        start_time = time.perf_counter()
        current_z = self.state
        
        for _ in range(self.length):
            current_z = pow(current_z, self.e, self.n) #current_z^e (mod n)
            bits.append(current_z % 2)
            
        end_time = time.perf_counter()
        return bits, end_time - start_time


class AES_CTR_Generator:
    def __init__(self, length_bits):
        self.length = length_bits
        self.key = os.urandom(32) 
        self.nonce = os.urandom(16)

    def generate(self):
        num_bytes = (self.length + 7) // 8 
        start_time = time.perf_counter()
        
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(self.nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        keystream = encryptor.update(b'\x00' * num_bytes) + encryptor.finalize()
        
        bits = []
        for byte in keystream:
            for i in range(8):
                if len(bits) < self.length:
                    bits.append((byte >> i) & 1)
        
        end_time = time.perf_counter()
        return bits, end_time - start_time


def run_analysis():
    lengths = [1000, 10000, 100000, 1000000] 
    
    results = {
        'BBS': {'times': [], 'zeros': [], 'space': []},
        'RSA': {'times': [], 'zeros': [], 'space': []},
        'AES': {'times': [], 'zeros': [], 'space': []}
    }

    print(f"{'Algo':<5} | {'Bits':<10} | {'Time (s)':<12} | {'0s Ratio':<10}")
    print("-" * 50)

    for l in lengths:
        # BBS
        bbs = BBS_Generator(l)
        bits, t = bbs.generate()
        results['BBS']['times'].append(t)
        results['BBS']['zeros'].append(bits.count(0))
        results['BBS']['space'].append(sys.getsizeof(bits))
        print(f"BBS   | {l:<10} | {t:.8f}   | {bits.count(0)/l:.4f}")

        # RSA
        rsa = RSA_Generator(l)
        bits, t = rsa.generate()
        results['RSA']['times'].append(t)
        results['RSA']['zeros'].append(bits.count(0))
        results['RSA']['space'].append(sys.getsizeof(bits))
        print(f"RSA   | {l:<10} | {t:.8f}   | {bits.count(0)/l:.4f}")

        # AES
        aes = AES_CTR_Generator(l)
        bits, t = aes.generate()
        
        if t < 1e-9: t = 1e-9 
        results['AES']['times'].append(t)
        results['AES']['zeros'].append(bits.count(0))
        results['AES']['space'].append(sys.getsizeof(bits))
        print(f"AES   | {l:<10} | {t:.8f}   | {bits.count(0)/l:.4f}")
        print("-" * 50)

    return lengths, results

def plot_graphs(lengths, results):
    # 1. TIME
    plt.figure(figsize=(10, 6))
    plt.plot(lengths, results['BBS']['times'], 'o-', color='red', label='BBS')
    plt.plot(lengths, results['RSA']['times'], '^-', color='green', label='RSA')
    plt.plot(lengths, results['AES']['times'], 's-', color='blue', label='AES')
    plt.xlabel('Bits Generated')
    plt.ylabel('Time (Seconds)')
    plt.title('Time Comparison (Log Scale)')
    plt.xscale('log')
    plt.yscale('log') 
    plt.grid(True, which="both", ls="-", alpha=0.5)
    plt.legend()
    try:
        plt.savefig('time_plot.png')
        print("Grafico salvato: time_plot.png")
        plt.show()
    except Exception as e:
        print(f"Impossibile mostrare il grafico: {e}")

    # 2. RANDOMNESS (Bias)
    plt.figure(figsize=(10, 6))
    r_bbs = [z/l for z, l in zip(results['BBS']['zeros'], lengths)]
    r_rsa = [z/l for z, l in zip(results['RSA']['zeros'], lengths)]
    r_aes = [z/l for z, l in zip(results['AES']['zeros'], lengths)]
    
    plt.plot(lengths, r_bbs, 'o-', color='red', label='BBS')
    plt.plot(lengths, r_rsa, '^-', color='green', label='RSA')
    plt.plot(lengths, r_aes, 's-', color='blue', label='AES')
    plt.axhline(0.5, color='black', linestyle='--')
    plt.ylim(0.40, 0.60)
    plt.xscale('log')
    plt.title('Randomness Bias (Target: 0.5)')
    plt.legend()
    plt.savefig('randomness_plot.png')
    plt.show()

if __name__ == "__main__":
    lengths, data = run_analysis()
    plot_graphs(lengths, data)
