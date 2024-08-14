import asyncio
import logging
from web3 import Web3
from eth_account import Account
from web3.exceptions import TransactionNotFound

# Set up logging
logging.basicConfig(filename='ethereum_transactions.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class EthereumTransactionManager:
    def __init__(self, private_key, from_address, contract_address, alchemy_api_key):
        self.web3 = Web3(Web3.HTTPProvider(f"https://eth-mainnet.alchemyapi.io/v2/{alchemy_api_key}"))
        self.account = Account.from_key(private_key)
        self.from_address = Web3.to_checksum_address(from_address)
        self.contract_address = Web3.to_checksum_address(contract_address)
        
        # ERC20 ABI (simplified for transfer function)
        self.erc20_abi = [{"constant":False,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"}]
        self.contract = self.web3.eth.contract(address=self.contract_address, abi=self.erc20_abi)
        logging.info(f"EthereumTransactionManager initialized for contract {self.contract_address}")

    async def create_and_broadcast_transaction(self, to, amount):
        try:
            to_address = Web3.to_checksum_address(to)
            
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

class TransactionError(Exception):
    pass

# Usage example
async def perform_transaction():
    try:
        manager = EthereumTransactionManager(
            private_key="1d810943752a2b2f85280a6149da40361600cae79789492431efc4ddf30630b5",
            from_address="0x5de2Aaf0F05460778A596C41426099eFc7fcA5e6",  # Your address
            contract_address="0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT contract address
            alchemy_api_key="fCcebZAowkk2-mwAqVFSNi-soow3_pk-"
        )
        
        amount = 1000 * 10**6  # 1000 USDT (6 decimal places)
        recipient_address = "0xf29d88ce699e64a2ba540e30c0eed988f2f59f51"
        
        tx_hash = await manager.create_and_broadcast_transaction(to=recipient_address, amount=amount)
        print(f"Transaction successful. Hash: {tx_hash}")
    except TransactionError as error:
        logging.error(f"Transaction failed: {str(error)}")
        print(f"Transaction failed: {str(error)}")
    except Exception as error:
        logging.error(f"Unexpected error: {str(error)}", exc_info=True)
        print(f"An unexpected error occurred. Please check the logs for details.")

# Run the transaction
if __name__ == "__main__":
    asyncio.run(perform_transaction())