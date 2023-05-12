# SalvoCrypt

## Descrizione

Il cifrario a chiave simmetrica SalvoCrypt è progettato per crittografare e decrittografare testo utilizzando una chiave simmetrica. Il codice è scritto in Python e offre un'implementazione semplice e rapida di un algoritmo di cifratura.

## Utilizzo

Per utilizzare il cifrario a chiave simmetrica, segui questi passaggi:

1. Assicurati di avere Python installato sul tuo sistema.
2. Importa la classe Cipher nel tuo codice: `from SC import Cipher`.
3. Crea un'istanza della classe Cipher specificando una costante: `cipher = Cipher(const)`.
4. Genera o imposta una chiave utilizzando il metodo `generate_key(length)` o `set_key(key)` della classe Cipher.
5. Per crittografare un testo, utilizza il metodo `encrypt(text)` specificando il testo da crittografare. Il metodo restituirà il testo crittografato.
6. Per decrittografare un testo crittografato, utilizza il metodo `decrypt(text)` specificando il testo crittografato. Il metodo restituirà il testo decrittografato.

Assicurati di rispettare i requisiti minimi per la lunghezza della chiave (4096 caratteri) quando generi o imposti una chiave.

## Esempio

Ecco un esempio di utilizzo del cifrario a chiave simmetrica:

```python
from SC import Cipher

cipher = Cipher(const)
cipher.generate_key(4096)

plaintext = "Questo è un messaggio da crittografare"
ciphertext = cipher.encrypt(plaintext)
decrypted_text = cipher.decrypt(ciphertext)

print("Testo originale:", plaintext)
print("Testo crittografato:", ciphertext)
print("Testo decrittografato:", decrypted_text)
```

## Contributi

Sono benvenuti contributi al progetto. Se desideri contribuire, puoi seguire questi passaggi:

    Fai una fork del repository.
    Crea un branch per il tuo contributo: git checkout -b nome-branch.
    Effettua le modifiche e i miglioramenti desiderati.
    Esegui i test e assicurati che tutto funzioni correttamente.
    Fai commit delle tue modifiche: git commit -m "Descrizione del tuo contributo".
    Effettua una push del branch: git push origin nome-branch.
    Apri una Pull Request nel repository originale.

## Autori

    Vittorio Salvatore Piccolo
