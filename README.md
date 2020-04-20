Project 3 (Ridikkulus Router)
=============================

(For build dependencies, please refer to [`Vagrantfile`](Vagrantfile).)

The starter code includes only the framework to receive raw Ethernet frames and to send Ethernet frames to the desired interfaces.  Your job is to implement the routers logic.

## Note for Gradescope Submission

This project can only be submitted to Gradescope via connection to GitHub (no raw file upload).

## Academic Integrity Note

You are encouraged to host your code in private repositories on [GitHub](https://github.com/), [GitLab](https://gitlab.com), or other places.  At the same time, you are PROHIBITED to make your code for the class project public during the class or any time after the class.  If you do so, you will be violating academic honestly policy that you have signed, as well as the student code of conduct and be subject to serious sanctions.

## Known Limitations

When POX controller is restrated, the simpler router needs to be manually stopped and started again.

## Acknowledgement

This implementation is based on the original code for Stanford CS144 lab3 (https://bitbucket.org/cs144-1617/lab3).

## TODO

Name and PID of each team member (up to 3 members in one team) and the contribution of each member
    Rebecca Dupuis 6056552
    Jason Davila 4953994
    Issachar Vinajeras 3007031


The high level design of your implementation
    This is an implementation of a router which receives packets and appropriately handles them. There are multiple parts to this. The router is able to handle ARP, ICMP, and IPv4 packets and will either forward the packet, respond, or deal with it if it was meant to arrive at the router.

The problems you ran into and how you solved the problems
    This assignment was challenging in that there are many parts to understanding how to deal with packets. First, we ran into the challenge of decoding and unpacking the ethernet frame in order to have the ARP or IPv4 packet. After this was done, it was easier to proceed.
    Another challenge of ours was dealing with checksum. At first we didn't know we needed to handle this and didn't understand why our ping was not working. Afterwards, we had trouble understanding how exactly to calculate it, but with the office hour help we figured it out.

List of any additional libraries used
    No additional libraries used.

Acknowledgement of any online tutorials or code example (except class website) you have been using.
    
