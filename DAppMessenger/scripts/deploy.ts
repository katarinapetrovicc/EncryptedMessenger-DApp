import * as dotenv from "dotenv";
import hre from "hardhat";
import { ethers } from "ethers"; // ethers v5
dotenv.config();

async function main() {
  console.log("Deploying EncryptedMessenger...");

  // ucitaj kompilovani ugovor
  const artifact = await hre.artifacts.readArtifact("EncryptedMessenger");

  // povezi se na sepolia mrezu 
  const provider = new ethers.providers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);

  // kreiraj novcanik iz privatnog kljuca
  const wallet = new ethers.Wallet(process.env.SEPOLIA_PRIVATE_KEY as string, provider);

  // kreiraj factory i deployuj ugovor
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, wallet);
  const contract = await factory.deploy();

  console.log("Deploying... čekaj potvrdu...");
  await contract.deployed();

  console.log("Ugovor uspešno deployovan!");
  console.log("Adresa:", contract.address);
}

main().catch((error) => {
  console.error("Deployment failed:", error);
  process.exitCode = 1;
});
