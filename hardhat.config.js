import { defineConfig } from "hardhat/config";

export default defineConfig({
  solidity: "0.8.24",
  paths: {
    sources: "./contracts",
    cache: "./cache",
    artifacts: "./artifacts"
  }
});
