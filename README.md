# International-Dollar

Github contributions will be rewarded with 1000-100000 International Dollars.
Just comment your IND address.

Setup process:
  1. git clone https://github.com/Hortofagos/International-Dollar.git
  2. pip install -r /path/to/requirements.txt
  3. python3 main.py


Node setup:
  1. Go to your router homepage. Search for "port forwarding" continue to forward PORT 8888 TCP & UDP + PORT 8887 UDP to your local ip.
  2 python3 node_client.py 

MacOS:
  1. brew install zbar
  2. delete tkextrafont & zbar from requirements.txt
  3. pip install -r /path/to/requirements.txt
  4. python3 main.py

If you want to convert your digital bills into physical ones, you can print them out yourself.
Go to the the tab "Win/Print" and write the serial numbers of the bills you
want to print in the grey box and click "Print bills". This requires you to have them in 
your wallet.

Dont forget to claim your free bills under "I'm feeling lucky".

There is absolutley NO WARRANTY

About 5,000 years ago that the Mesopotamian people created the shekel,
which is considered the first known form of currency. Since then,
we have come a long way in our monetary system. From Gold and Silver
coins, to banknotes, to wire transfers and eventually to
cryptocurrencies. Bitcoin, the first cryptocurrency created in 2009,
has started a revolution, spawning a number of new coins based
on the same blockchain technology. Now in 2022 this project is
the next step in our fiscal evolution. With a simple majority based
voting algorithm, we believe that we can deliver the same security
as the Bitcoin Blockchain. You might ask why we didn't choose the
trusted blockchain? Well our algorithm has a lot of advantages
ranging from instant and free transactions to 99.9% less energy
consumption. But most importantly, we do not seek a financial gain
from this project, all International Dollars will be slowly and
equally distributed across the community. This is not about getting
rich quick, this is about creating a fair financial system one step at a time.

POWER TO THE PEOPLE
---------------------------------------------------------------------------------

*How does our new POI (Proof of IP) algorithm work?*


Each time, a user needs to determine the rightful owner of an International
Dollar bill, a democratic election cycle  is held. The User asks all nodes
(+ 10 UDP nodes behind NAT), to cast in their vote. The votes are counted,
and if the majority agrees that the bill belongs to the user's address, a consensus
has been reached. All it takes to cast a vote is a valid IPv4 address,
that is online and reachable, ergo PROOF OF IP. Now this system can only
work with many users who voluntarily run a node. We are banking on the fact, that these average users
WILL NOT run a maliciuos node with corrupted data. Therefore they create our basis of truth.
Our calculations show that just 1100 average user nodes, is enough to protect even 
against the strongest efforts, to gain an unffair network majority.
Try getting 1101 different IPv4 addresses, all coming from hundreds of different IP blocks.
You can't.
That's the reason we made it extremeley easy to join the network. One click is enough to run a small
node. In most cases, there is no need to manually open PORT 8888/8887 TCP & UDP,
since we implemented UPnP port forwarding and UDP hole punching techniques.
But just a large user base, which runs a node is not enough to gurantee security, therefore we also put 
various security measures in place:
	- We limit the number of votes from the same IP block:
		class A block with 16.7 million addresses (/8): 32 votes
		class B block with 65 thousand addresses (/16): 4 votes
		class C block with 256 addresses (/24): 1 vote
	  This prevents an Organization (like an ISP) which already owns millions of addresses
	  to take over the network majority. Since most of their addresses come from a few
	  big IP blocks.
	- IPv6 clients are prohibited from running a node, since their address number
	  is not tightly limited.
	- We prevented IP spoofing by using the TCP protocol in combination with an RSA
	  key exchange and encrypting the following data (for main nodes).
	  For smaller UDP nodes, that are behind a NAT, the client generates a random
	  string, which the node server has to echo.
	- We greatly increased the voting power of the founder node (172.86.121.72).
	  For the next few years, the voting power of this node will gradually decrease,
	  until it nullifies (hard-coded UNIX time 1800000000).
