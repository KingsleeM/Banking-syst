import hashlib
import json
import os
import secrets
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path


DATA_FILE = Path(os.environ.get("BANK_DATA_FILE", Path(__file__).with_name("bank_data.json")))


def money(cents):
	return f"R{cents // 100:,}.{cents % 100:02d}"


def valid_cents(cents):
	return isinstance(cents, int) and not isinstance(cents, bool) and cents > 0


def read_amount(prompt):
	try:
		amount = Decimal(input(prompt).strip())
		cents = amount * 100
		if not amount.is_finite() or cents != cents.to_integral_value() or cents <= 0:
			raise ValueError
		return int(cents)
	except (InvalidOperation, ValueError):
		print("Enter an amount greater than zero with at most two decimal places.")
		return None


def pin_digest(pin, salt):
	return hashlib.pbkdf2_hmac("sha256", pin.encode(), bytes.fromhex(salt), 200_000).hex()


class Bank:
	def __init__(self, data_file):
		self.data_file = Path(data_file)
		self.accounts = {}
		self.load()

	def load(self):
		if self.data_file.exists():
			try:
				loaded_accounts = json.loads(self.data_file.read_text(encoding="utf-8"))
			except (json.JSONDecodeError, OSError) as error:
				raise RuntimeError(f"Could not read bank data: {error}") from error
			if not isinstance(loaded_accounts, dict):
				raise RuntimeError("Could not read bank data: the root value must be an object.")
			for account_number, account in loaded_accounts.items():
				if (
					not isinstance(account_number, str)
					or not account_number.isdigit()
					or len(account_number) != 10
					or not isinstance(account, dict)
					or not isinstance(account.get("name"), str)
					or not isinstance(account.get("salt"), str)
					or not isinstance(account.get("pin_hash"), str)
					or not isinstance(account.get("balance_cents"), int)
					or account["balance_cents"] < 0
					or not isinstance(account.get("transactions"), list)
				):
					raise RuntimeError(f"Could not read bank data: invalid account {account_number!r}.")
			self.accounts = loaded_accounts

	def save(self):
		self.data_file.parent.mkdir(parents=True, exist_ok=True)
		temporary_file = self.data_file.with_suffix(self.data_file.suffix + ".tmp")
		temporary_file.write_text(json.dumps(self.accounts, indent=2), encoding="utf-8")
		temporary_file.replace(self.data_file)

	def create_account(self, name, pin):
		if not isinstance(name, str) or not name.strip():
			raise ValueError("Name cannot be empty.")
		if not isinstance(pin, str) or not pin.isdigit() or not 4 <= len(pin) <= 12:
			raise ValueError("PIN must contain 4-12 digits.")
		account_number = str(secrets.randbelow(9_000_000_000) + 1_000_000_000)
		while account_number in self.accounts:
			account_number = str(secrets.randbelow(9_000_000_000) + 1_000_000_000)
		salt = secrets.token_bytes(16).hex()
		self.accounts[account_number] = {
			"name": name,
			"salt": salt,
			"pin_hash": pin_digest(pin, salt),
			"balance_cents": 0,
			"transactions": [],
		}
		self.save()
		return account_number

	def authenticate(self, account_number, pin):
		account = self.accounts.get(account_number)
		if account is None:
			return False
		return secrets.compare_digest(account["pin_hash"], pin_digest(pin, account["salt"]))

	def record(self, account_number, kind, cents, note):
		account = self.accounts[account_number]
		account["transactions"].append({
			"time": datetime.now().isoformat(timespec="seconds"),
			"type": kind,
			"amount_cents": cents,
			"note": note,
		})

	def deposit(self, account_number, cents):
		if not valid_cents(cents):
			raise ValueError("Amount must be a positive whole number of cents.")
		self.accounts[account_number]["balance_cents"] += cents
		self.record(account_number, "Deposit", cents, "Cash deposit")
		self.save()

	def withdraw(self, account_number, cents):
		if not valid_cents(cents):
			raise ValueError("Amount must be a positive whole number of cents.")
		account = self.accounts[account_number]
		if cents > account["balance_cents"]:
			return False
		account["balance_cents"] -= cents
		self.record(account_number, "Withdrawal", cents, "Cash withdrawal")
		self.save()
		return True

	def transfer(self, sender_number, recipient_number, cents):
		if not valid_cents(cents):
			raise ValueError("Amount must be a positive whole number of cents.")
		if recipient_number == sender_number or recipient_number not in self.accounts:
			return False
		sender = self.accounts[sender_number]
		if cents > sender["balance_cents"]:
			return False
		sender["balance_cents"] -= cents
		self.accounts[recipient_number]["balance_cents"] += cents
		self.record(sender_number, "Transfer sent", cents, f"To {recipient_number}")
		self.record(recipient_number, "Transfer received", cents, f"From {sender_number}")
		self.save()
		return True


def create_account(bank):
	name = input("Your name: ").strip()
	if not name:
		print("Name cannot be empty.")
		return
	pin = input("Choose a 4-12 digit PIN: ").strip()
	if not pin.isdigit() or not 4 <= len(pin) <= 12:
		print("PIN must contain 4-12 digits.")
		return
	account_number = bank.create_account(name, pin)
	print(f"Account created for {name}. Your account number is {account_number}.")
	print("Keep your account number private; your opening balance is R0.00.")


def account_menu(bank, account_number):
	account = bank.accounts[account_number]
	print(f"\nWelcome, {account['name']}.")
	while True:
		print("\n1. Check balance  2. Deposit  3. Withdraw")
		print("4. Transfer       5. Transactions  6. Log out")
		choice = input("Choose an option: ").strip()
		if choice == "1":
			print(f"Balance: {money(account['balance_cents'])}")
		elif choice in ("2", "3"):
			cents = read_amount("Amount: R")
			if cents is None:
				continue
			if choice == "2":
				bank.deposit(account_number, cents)
				print(f"Deposited {money(cents)}. New balance: {money(account['balance_cents'])}")
			elif bank.withdraw(account_number, cents):
				print(f"Withdrew {money(cents)}. New balance: {money(account['balance_cents'])}")
			else:
				print("Insufficient funds.")
		elif choice == "4":
			recipient = input("Recipient account number: ").strip()
			cents = read_amount("Amount: R")
			if cents is None:
				continue
			if bank.transfer(account_number, recipient, cents):
				print(f"Transferred {money(cents)} to {recipient}.")
			else:
				print("Transfer failed. Check the account number and available balance.")
		elif choice == "5":
			transactions = account["transactions"]
			if not transactions:
				print("No transactions yet.")
			else:
				for transaction in transactions:
					print(
						f"{transaction['time']} | {transaction['type']} "
						f"{money(transaction['amount_cents'])} | {transaction['note']}"
					)
		elif choice == "6":
			print("Logged out.")
			return
		else:
			print("Choose a number from 1 to 6.")


def main():
	try:
		bank = Bank(DATA_FILE)
		print("=== Community Bank (local simulator) ===")
		while True:
			print("\n1. Create account  2. Log in  3. Exit")
			choice = input("Choose an option: ").strip()
			if choice == "1":
				create_account(bank)
			elif choice == "2":
				account_number = input("Account number: ").strip()
				pin = input("PIN: ").strip()
				if bank.authenticate(account_number, pin):
					account_menu(bank, account_number)
				else:
					print("Invalid account number or PIN.")
			elif choice == "3":
				print("Goodbye.")
				return
			else:
				print("Choose 1, 2, or 3.")
	except (OSError, RuntimeError) as error:
		print(f"Bank data error: {error}")


if __name__ == "__main__":
	main()