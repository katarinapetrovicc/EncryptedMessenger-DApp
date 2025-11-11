## EncryptedMessenger DApp
Decentralizovana aplikacija za razmenu enkriptovanih poruka u realnom vremenu korišćenjem Ethereum blockchain-a, Hardhat okruženja i kriptografskih algoritama (AES + RSA).  
Aplikacija obezbeđuje bezbedan kanal komunikacije između korisnika — poruke su šifrovane, a na blockchain se čuvaju samo metapodaci (hash, adrese i vreme).

## Opis projekta

Cilj projekta je razvoj decentralizovane aplikacije (DApp) koja omogućava:
- slanje i primanje šifrovanih poruka u realnom vremenu,  
- čuvanje samo metapodataka (hash, pošiljalac, primalac, vreme) na blockchain-u,  
- lokalno čuvanje šifrovanih poruka na korisničkoj strani (browser storage),  
- autentičnost putem digitalnog potpisa i integritet pomoću hash funkcije (SHA-256),  
- sigurnu razmenu ključeva pomoću RSA asimetrične enkripcije.  

Blockchain se koristi isključivo za proveru autentičnosti i integriteta komunikacije, dok se sadržaj poruka čuva lokalno kod korisnika.

## Struktura projekta
 ```
EncryptedMessenger-DApp/
│
├── DAppMessenger/ # Backend (Hardhat + pametni ugovor)
│ ├── contracts/ # Solidity ugovori
│ ├── scripts/ # Deploy i pomoćne skripte
│ ├── test/ # Automatizovani testovi
│ ├── hardhat.config.ts # Konfiguracija Hardhat okruženja
│ └── package.json
│
├── dapp-frontend/ # Frontend (React + Ethers.js)
│ ├── src/ # Komponente, logika enkripcije i UI
│ ├── public/
│ └── package.json
│
└── README.md # Opis projekta
 ```

## Preduslovi
Pre nego što se pokrene projekat, potrebno je imati instalirano:
- [Node.js (v18+)](https://nodejs.org/)
- [npm](https://www.npmjs.com/)
- [MetaMask](https://metamask.io/)
- [Hardhat](https://hardhat.org/)
- [Git](https://git-scm.com/)


## Klonirati repozitorijum
```bash
git clone https://github.com/katarinapetrovicc/EncryptedMessenger-DApp.git
cd EncryptedMessenger-DApp

## Instalirati zavisnosti za backend (Hardhat)
cd DAppMessenger
npm install

## Instalirati zavisnosti za frontend (React)
cd ../dapp-frontend
npm install


## Pokretanje projekta (lokalno)
Pokrenuti lokalni blockchain (Hardhat node)
cd DAppMessenger
npx hardhat node

## Deployuj pametni ugovor
U drugom terminalu (dok node radi):
npx hardhat run scripts/deploy.js --network localhost

## Pokrenuti frontend aplikaciju
cd ../dapp-frontend
npm start

## Frontend se otvara na:
http://localhost:3000

## Povezati MetaMask
U MetaMask-u izaberati mrežu Localhost 8545
Odabrati jedan od Hardhat naloga (vidi se u terminalu pri pokretanju npx hardhat node)
Nakon povezivanja može da se šalju i primaju poruke

## Pokretanje testova
U Hardhat projektu:
cd DAppMessenger
npx hardhat test

## Testovi proveravaju:
validno slanje poruka
emitovanje događaja MessageSent
proveru potpisa i autentičnosti
sprečavanje neovlašćenog čitanja poruka
Rezultati testiranja biće prikazani u terminalu.


## Korišćenje aplikacije
Pokrenuti lokalni node i frontend (npm start)
Povezati MetaMask
Uneti adresu primaoca i poruku
Kliknuti na Pošalji
Poruka se šifruje (AES), njen hash upisuje na blockchain, a šifrovani sadržaj se čuva lokalno.
