from cryptography.fernet import Fernet

# Generate a new Fernet key and decode it to a string
key = Fernet.generate_key().decode() 

# Path to .env file
env_file_path = "website/.env"

# Append the encryption key to the .env file
with open(env_file_path, "a") as env_file:
    env_file.write(f"\nENCRYPTION_KEY={key}\n")

print(f"Encryption key generated and added to {env_file_path}")
