To run this project just first create a network "netsec" and make it driver:brige and internal:true.

Then, run the Dockerfile_base_system docker build:
it will build the ubuntu container with all the dependencies useful to all three
containers (client, attacker and server), especially those needed to sniff and arp poison (attacker)!

Then, run the compose.yaml file for the demo. It will spawn three containers, first that of the attacker, which will
begin arppoisoning