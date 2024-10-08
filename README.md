# SalvoCrypt - IT

## Descrizione

SalvoCrypt è un progetto che implementa un cifrario personalizzato con l'obiettivo di fornire una soluzione di crittografia sicura e robusta. La versione 2.0 del cifrario presenta miglioramenti significativi rispetto alla versione precedente, tra cui un aumento della sicurezza e un’ottimizzazione della generazione delle chiavi.

### Caratteristiche
- **Lunghezza minima della chiave**: 4096 bit per una protezione robusta.
- **Generazione delle chiavi ottimizzata**: Algoritmi migliorati per chiavi uniche.
- **Gestione delle chiavi migliorata**: Metodi più chiari per il caricamento e la convalida delle chiavi.
- **Algoritmo di crittografia raffinato**: Maggiore complessità nella decrittazione non autorizzata.
- **Supporto per la codifica Base64**: Per una trasmissione e archiviazione sicura.
- **Struttura del codice**: Riorganizzazione per una migliore leggibilità e manutenibilità.

## Utilizzo

1. Clona il repository:
   ```bash
   git clone https://github.com/Vit8816/SalvoCrypt.git
   ```
2. Installa le dipendenze necessarie.
   ```bash
   pip install numpy
   ```
4. Esegui il programma per testare il cifrario.
```python
cip = Cipher(3)
cip.generate_key(4096)
clear = "Ciao, questo testo è una prova del cifrario"
enc = cip.encrypt(clear)
print(enc)
dec = cip.decrypt(enc)
print(dec)
```

## Contribuire

Le collaborazioni sono benvenute! Sentiti libero di aprire un problema o una richiesta di pull.

---

# SalvoCrypt - EN

## Description

SalvoCrypt is a project that implements a custom cipher aimed at providing a secure and robust encryption solution. Version 2.0 of the cipher features significant improvements over the previous version, including enhanced security and optimized key generation.

### Features
- **Minimum Key Length**: 4096 bits for robust protection.
- **Optimized Key Generation**: Improved algorithms for unique keys.
- **Enhanced Key Management**: Clearer methods for loading and validating keys.
- **Refined Encryption Algorithm**: Increased complexity in unauthorized decryption.
- **Base64 Encoding Support**: For secure transmission and storage.
- **Code Structure**: Reorganized for better readability and maintainability.

## Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/Vit8816/SalvoCrypt.git
   ```
2. Install necessary dependencies.
   ```bash
   pip install numpy
   ```
4. Run the program to test the cipher.
  ```python
cip = Cipher(3)
cip.generate_key(4096)
clear = "Hello, this text is a test of the cipher"
enc = cip.encrypt(clear)
print(enc)
dec = cip.decrypt(enc)
print(dec)
```

## Contributing

Contributions are welcome! Feel free to open an issue or a pull request.
