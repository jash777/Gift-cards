import asyncio
import logging
from web3 import Web3
from eth_account import Account
from web3.exceptions import TransactionNotFound
import tenacity
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(filename='ethereum_transactions.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class EthereumTransactionManager:
    def __init__(self):
        self.web3 = Web3(Web3.HTTPProvider(f"https://eth-mainnet.alchemyapi.io/v2/{os.getenv('ALCHEMY_API_KEY')}"))
        self.account = Account.from_key(os.getenv('PRIVATE_KEY'))
        self.from_address = Web3.to_checksum_address(os.getenv('FROM_ADDRESS'))
        self.contract_address = Web3.to_checksum_address(os.getenv('CONTRACT_ADDRESS'))
        
        # ERC20 ABI (more complete version)
        self.erc20_abi = [
            {"constant":True,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"type":"function"},
            {"constant":False,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"},
            {"constant":True,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"},
            {"constant":True,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"type":"function"}
        ]
        self.contract = self.web3.eth.contract(address=self.contract_address, abi=self.erc20_abi)
        logging.info(f"EthereumTransactionManager initialized for contract {self.contract_address}")

    async def create_and_broadcast_transaction(self, to, amount):
        try:
            to_address = Web3.to_checksum_address(to)
            
            # Check balances
            await self.check_balances(amount)
            
            # Get the current nonce
            nonce = self.web3.eth.get_transaction_count(self.from_address)
            
            # Estimate gas price and limit
            gas_price = self.web3.eth.gas_price
            gas_limit = await self.estimate_gas(to_address, amount)
            
            # Prepare the transaction
            transaction = self.contract.functions.transfer(to_address, amount).build_transaction({
                'chainId': 1,
                'gas': gas_limit,
                'gasPrice': gas_price,
                'nonce': nonce,
            })
            
            # Log transaction details
            logging.info(f"Transaction prepared: To: {to_address}, Amount: {amount}, Gas: {gas_limit}, Gas Price: {gas_price}, Nonce: {nonce}")
            
            # Sign the transaction
            signed_txn = self.account.sign_transaction(transaction)
            
            # Broadcast the transaction
            tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            # Wait for transaction confirmation
            await self.wait_for_transaction_confirmation(tx_hash.hex())
            
            logging.info(f"Transaction successful. Hash: {tx_hash.hex()}")
            return tx_hash.hex()
        except Exception as e:
            logging.error(f"Error in create_and_broadcast_transaction: {str(e)}", exc_info=True)
            raise TransactionError(f"Failed to create and broadcast transaction: {str(e)}")

    @tenacity.retry(stop=tenacity.stop_after_attempt(3), wait=tenacity.wait_fixed(2))
    async def estimate_gas(self, to, amount):
        try:
            gas_estimate = self.contract.functions.transfer(to, amount).estimate_gas({'from': self.from_address})
            logging.info(f"Gas estimated: {gas_estimate}")
            return gas_estimate
        except Exception as e:
            logging.error(f"Error in estimate_gas: {str(e)}", exc_info=True)
            raise TransactionError(f"Failed to estimate gas: {str(e)}")

    async def wait_for_transaction_confirmation(self, tx_hash, max_attempts=50, delay_seconds=15):
        for attempt in range(max_attempts):
            try:
                receipt = self.web3.eth.get_transaction_receipt(tx_hash)
                if receipt is not None:
                    if receipt['status'] == 1:
                        logging.info(f"Transaction confirmed: {tx_hash}")
                        return
                    else:
                        logging.error(f"Transaction failed: {tx_hash}")
                        raise TransactionError("Transaction failed")
            except TransactionNotFound:
                logging.info(f"Transaction not found, attempt {attempt + 1}/{max_attempts}")
            await asyncio.sleep(delay_seconds)
        logging.error(f"Transaction timeout: {tx_hash}")
        raise TransactionError("Transaction timeout")

    async def check_balances(self, amount):
        token_balance = await self.check_token_balance()
        if token_balance < amount:
            raise TransactionError(f"Insufficient token balance. Available: {token_balance}, Required: {amount}")
        
        eth_balance = await self.check_eth_balance()
        if eth_balance < self.web3.to_wei(0.1, 'ether'):
            raise TransactionError(f"Low ETH balance. Available: {self.web3.from_wei(eth_balance, 'ether')} ETH")

    async def check_token_balance(self):
        balance = self.contract.functions.balanceOf(self.from_address).call()
        symbol = self.contract.functions.symbol().call()
        decimals = self.contract.functions.decimals().call()
        adjusted_balance = balance / (10 ** decimals)
        logging.info(f"Token balance: {adjusted_balance} {symbol}")
        return balance

    async def check_eth_balance(self):
        balance = self.web3.eth.get_balance(self.from_address)
        eth_balance = self.web3.from_wei(balance, 'ether')
        logging.info(f"ETH balance: {eth_balance} ETH")
        return balance

class TransactionError(Exception):
    pass

async def perform_transaction():
    try:
        manager = EthereumTransactionManager()
        
        amount = 1000 * 10**6  # 1000 USDT (6 decimal places)
        recipient_address = os.getenv('RECIPIENT_ADDRESS')
        
        tx_hash = await manager.create_and_broadcast_transaction(to=recipient_address, amount=amount)
        print(f"Transaction successful. Hash: {tx_hash}")
    except TransactionError as error:
        logging.error(f"Transaction failed: {str(error)}")
        print(f"Transaction failed: {str(error)}")
    except Exception as error:
        logging.error(f"Unexpected error: {str(error)}", exc_info=True)
        print(f"An unexpected error occurred. Please check the logs for details.")

if __name__ == "__main__":
    asyncio.run(perform_transaction())