# International-Dollar

Github contributions will be rewarded with 1000-100000 International Dollars.
Just comment your IND address.

![Aufzeichnung-2023-08-26-213911](https://github.com/Hortofagos/International-Dollar/assets/120664745/7aaf7b25-1f2a-42f6-8ca0-838bfd39a762)

# International Dollar (IND) Setup Guide

Welcome to International Dollar (IND), the next step in the evolution of our fiscal system. IND is a cryptocurrency project that aims to provide a fair and secure financial system for all. Unlike traditional blockchain-based cryptocurrencies, IND uses a unique Proof of IP (POI) algorithm, designed to be energy-efficient and community-driven. This setup guide will help you get started with IND on various platforms.

## Getting Started

### Clone the Repository
To begin, you'll need to clone the IND repository to your local machine:

```bash
git clone https://github.com/Hortofagos/International-Dollar.git
```

### Install Dependencies

#### General Setup
For most setups, follow these steps:

```bash
pip install -r /path/to/requirements.txt
python3 main.py
```

#### Node Setup
If you intend to run a node, please ensure you set up port forwarding for PORT 8888 (TCP & UDP) and PORT 8887 (UDP) on your router. This is necessary for node communication. Then, run the node client:

```bash
python3 node_client.py
```

#### MacOS Setup
For MacOS users, follow these additional steps:

```bash
brew install zbar
pip install -r /path/to/requirements.txt
python3 main.py
```

## Printing Digital Bills

If you wish to convert your digital bills into physical ones, you can print them yourself. Follow these steps:

1. Go to the "Win/Print" tab in the application.
2. Enter the serial numbers of the bills you want to print in the grey box.
3. Click "Print bills." Ensure you have the printed bills in your wallet.

## Claim Your Free Bills

Don't forget to claim your free bills under the "I'm feeling lucky" section.

## Disclaimer

Please note that there is absolutely NO WARRANTY provided with this project.

## Repository File Explanation

- **files**: contains all the .txt files needed for node and main.py operation
      - *check_signed_in.txt*: Contains information if the user wants to stay signed in or not.
      - *hashing.txt*: Used in the generation process.
      - *kill_node.txt*: Used to kill a running node.
      - *last_luck.txt*: Contains UNIX time of the last free bill request.
      - *my_public_ip.txt*: Contains your public IP address in case you run a node.
      - *node_class.txt*: Contains information if the user wants to run a full node or a small node.
      - *passphrase.txt*: Used to encode the wallet.
      - *rsa_private_key.txt*: Contains the RSA private key used to decrypt data between node/client.
      - *rsa_public_key.txt*: Contains the RSA public key used to encrypt data between node/client.
      - *spam_protection.txt*: Used by nodes to protect against spam.
- **full_activation**: Contains information about the download state of the database (node_bills.db).
- **img**: Contains all GUI images and buttons.
- **ip_folder**: Stores all IPs from the node network.
- **print_folder**: Used in generating printable bill documents.
- **transaction_folder**: Stores generated transactions temporarily.
- **LICENSE.txt**: Contains the open-source license.
- **README.md**: The file you are currently reading.
- **confirm_validity.py**: Confirms ECDSA signatures.
- **generate_address.py**: Generates IND addresses.
- **ind_font.ttf**: Contains the font used.
- **main.py**: The main application that combines the Tkinter GUI with the backend.
- **node_bills.db**: Contains the entire database.
- **node_client.py**: The python file containing the full node.
- **portforwardlib.py**: Used to UPNP forward PORT 8888 and 8887.
- **print.py**: Generates printable paper wallets (IND bills).
- **requirements.txt**: Contains all python dependencies.
- **sender_node.py**: Used by the client to communicate with nodes.
- **udp_hole_node.py**: Used for small UDP nodes behind NAT.
- **wallet_decryption.py**: Decrypts wallets stored in wallet_folder.
- **wallet_encryption.py**: Encrypts wallets.

## About International Dollar (IND)

International Dollar (IND) represents the next step in the evolution of currency systems, building on a history that dates back over 5,000 years to the creation of the shekel in Mesopotamia. IND is designed to provide a fair and secure financial system, with a focus on community and sustainability. It offers a range of advantages, including instant and free transactions and significantly reduced energy consumption compared to traditional blockchain-based cryptocurrencies.

## How the Proof of IP (POI) Algorithm Works

IND's unique Proof of IP (POI) algorithm ensures the rightful owner of an International Dollar bill is determined through a democratic election cycle. Here's how it works:

1. Users initiate a request to determine the rightful owner of a bill.
2. All nodes, including 10 UDP nodes behind NAT, cast their votes.
3. The votes are counted, and if the majority agrees with the user's address, a consensus is reached.
4. To cast a vote, a valid IPv4 address that is online and reachable is required, providing Proof of IP.

This system relies on a community of users running nodes voluntarily. We trust that these users will not run malicious nodes with corrupted data, creating a basis of truth. With just 1,100 average user nodes, even the strongest attempts to gain an unfair network majority can be thwarted. This high threshold makes it extremely difficult for any entity to control the network.

Additional security measures include limiting the number of votes from the same IP block, prohibiting IPv6 clients from running nodes, and preventing IP spoofing through encryption and key exchange protocols.

IND's founder node holds significant initial voting power, which will gradually decrease over the next few years, ensuring decentralization over time.

This project is driven by a commitment to create a fair financial system, one step at a time, with power vested in the community. Join us in this revolutionary fiscal evolution. POWER TO THE PEOPLE!
